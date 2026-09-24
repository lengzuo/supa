# supa: Supabase client for Go

`supa` is a Go client for [Supabase](https://supabase.com): Auth, Database
(PostgREST), Storage, Edge Functions and Realtime. Version 2 targets feature
parity with the official [supabase-js](https://github.com/supabase/supabase-js)
client, checked feature by feature against the upstream capability matrix
(see [Feature parity](#feature-parity)). It uses the standard library plus one
websocket dependency, is safe for concurrent use, and every network call takes
a `context.Context`.

- Module: `github.com/lengzuo/supa/v2` (in [`v2/`](v2/))
- API reference: [pkg.go.dev/github.com/lengzuo/supa/v2](https://pkg.go.dev/github.com/lengzuo/supa/v2)
- The legacy v1 package at the repository root is superseded by v2; see
  [Migrating from v1](#migrating-from-v1).

## Contents

- [Install](#install)
- [Quick start](#quick-start)
- [Auth](#auth)
- [Database](#database)
- [Storage](#storage)
- [Edge Functions](#edge-functions)
- [Realtime](#realtime)
- [Third-party auth](#third-party-auth)
- [HTTP client, headers and logging](#http-client-headers-and-logging)
- [Tracing](#tracing)
- [Server-side usage and security](#server-side-usage-and-security)
- [Error handling](#error-handling)
- [Feature parity](#feature-parity)
- [Migrating from v1](#migrating-from-v1)
- [Development](#development)

## Install

```sh
go get github.com/lengzuo/supa/v2
```

Requires Go 1.23 or later.

```go
import (
	supabase "github.com/lengzuo/supa/v2"
	"github.com/lengzuo/supa/v2/auth" // and postgrest, storage, functions, realtime as needed
)
```

## Quick start

```go
ctx := context.Background()

client, err := supabase.New(
	supabase.ProjectURL("your-project-ref"), // https://your-project-ref.supabase.co
	os.Getenv("SUPABASE_PUBLISHABLE_KEY"),   // publishable (sb_publishable_...) or legacy anon key
	nil,                                     // *supabase.Options; nil uses the defaults
)
if err != nil {
	log.Fatal(err)
}
defer func() { _ = client.Close(ctx) }()

var todos []Todo
if _, err := client.From("todos").Select("*").Eq("done", false).ExecuteInto(ctx, &todos); err != nil {
	log.Fatal(err)
}
fmt.Println(len(todos), "open todos")
```

`client` exposes `Auth`, `Storage`, `Functions` and `Realtime`, plus `From`,
`RPC`, `Schema` and `DB()` for the database. Every service is also usable on
its own through its package (`auth.New`, `postgrest.New`, `storage.New`,
`functions.New`, `realtime.New`).

For local development (`supabase start`) or a self-hosted instance, pass the
API gateway URL instead of `ProjectURL`:

```go
client, err := supabase.New("http://127.0.0.1:54321", os.Getenv("SUPABASE_PUBLISHABLE_KEY"), nil)
```

The snippets below assume `ctx` and `client` from the quick start. Each one is
a compiled example in [`v2/example_test.go`](v2/example_test.go) or a
package's `example_test.go`.

## Auth

`client.Auth` is an [`*auth.Client`](https://pkg.go.dev/github.com/lengzuo/supa/v2/auth).
By default it keeps one current session in memory, like supabase-js in a
browser, and the other services send that session's access token. Servers
that handle many users should read
[Server-side usage and security](#server-side-usage-and-security) first.

### Sign up and sign in with a password

```go
res, err := client.Auth.SignUp(ctx, auth.SignUpParams{
	Email:    "ada@example.com",
	Password: "correct-horse-battery-staple",
	Data:     map[string]any{"display_name": "Ada"}, // user_metadata
})
if err != nil {
	log.Fatal(err)
}
if res.Session == nil {
	fmt.Println("check your inbox to confirm", res.User.Email)
}
```

```go
res, err := client.Auth.SignInWithPassword(ctx, auth.SignInWithPasswordParams{
	Email:    "ada@example.com",
	Password: "correct-horse-battery-staple",
})
if err != nil {
	log.Fatal(err)
}
fmt.Println("signed in as", res.User.ID)
// The session is now stored in the client: From, Storage, Functions and
// Realtime send its access token automatically.
```

Also available: `SignInAnonymously`, `SignInWithIDToken`, `SignInWithSSO`,
`SignInWithWeb3`, `ResetPasswordForEmail`, `UpdateUser`, `Resend`,
identity linking and passkeys (`client.Auth.Passkey()`).

### One-time passwords

```go
// 1. Send a one-time code (or magic link) by email.
if _, err := client.Auth.SignInWithOTP(ctx, auth.SignInWithOTPParams{Email: "ada@example.com"}); err != nil {
	log.Fatal(err)
}

// 2. Verify the code the user typed in.
res, err := client.Auth.VerifyOTP(ctx, auth.VerifyOTPParams{
	Email: "ada@example.com",
	Token: "123456",
	Type:  auth.OTPTypeEmail,
})
if err != nil {
	log.Fatal(err)
}
fmt.Println("signed in:", res.Session != nil)
```

### OAuth with PKCE

`SignInWithOAuth` makes no request; it returns the URL to send the user to.
With `auth.FlowPKCE` the code verifier is kept in the client's
`SessionStorage` until the callback.

```go
client, err := supabase.New(supabase.ProjectURL("your-project-ref"), os.Getenv("SUPABASE_PUBLISHABLE_KEY"), &supabase.Options{
	Auth: auth.Config{FlowType: auth.FlowPKCE},
})
if err != nil {
	log.Fatal(err)
}

// 1. Send the user to the provider.
oauth, err := client.Auth.SignInWithOAuth(ctx, auth.SignInWithOAuthParams{
	Provider:   "github",
	RedirectTo: "https://example.com/auth/callback",
})
if err != nil {
	log.Fatal(err)
}
fmt.Println("redirect the user to", oauth.URL)

// 2. In the callback handler, exchange the ?code=... for a session.
// NoStore returns the session without making it the client's own session,
// which is what a server shared between users needs; hand the tokens to
// the user (e.g. in a cookie) instead.
http.HandleFunc("/auth/callback", func(w http.ResponseWriter, r *http.Request) {
	res, err := client.Auth.ExchangeCodeForSession(r.Context(), r.URL.Query().Get("code"),
		&auth.ExchangeCodeOptions{NoStore: true})
	// Or let the SDK read code / error parameters from the URL:
	//   res, err := client.Auth.GetSessionFromURL(r.Context(), r.URL.String(),
	//       &auth.GetSessionFromURLOptions{NoStore: true})
	if err != nil {
		http.Error(w, "sign-in failed", http.StatusUnauthorized)
		return
	}
	_ = json.NewEncoder(w).Encode(res.User)
})
```

The verifier lives in the client that started the flow. On a server with many
users, start and finish each flow with a client whose `SessionStorage` is
scoped to that user (for example, one backed by a cookie or your session
store); see [Custom session storage](#custom-session-storage). Use
`ExchangeCodeOptions{NoStore: true}` (or `GetSessionFromURLOptions{NoStore:
true}`) so the resulting session is returned to you rather than becoming the
client's own session: without it, one user's callback would make later calls
on a shared client run as that user. The verifier is removed from storage as
soon as it has been read.

### Verify a user's JWT on a server

```go
// On a server, authenticate each request by validating the caller's JWT
// with the Auth server. Never trust an unverified token or GetSession.
http.HandleFunc("/api/me", func(w http.ResponseWriter, r *http.Request) {
	jwt := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	user, err := client.Auth.GetUser(r.Context(), jwt)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	_ = json.NewEncoder(w).Encode(user)
})
```

`GetClaims(ctx, jwt, nil)` verifies asymmetrically signed JWTs locally against
the project's JWKS (cached), falling back to the Auth server otherwise.

### Sessions, auto-refresh and auth events

```go
client, err := supabase.New(supabase.ProjectURL("your-project-ref"), os.Getenv("SUPABASE_PUBLISHABLE_KEY"), &supabase.Options{
	// Refresh the stored session in the background before it expires.
	Auth: auth.Config{AutoRefreshToken: true},
})
if err != nil {
	log.Fatal(err)
}
defer func() { _ = client.Close(ctx) }() // stops auto-refresh and Realtime

unsubscribe := client.Auth.OnAuthStateChange(func(event auth.AuthChangeEvent, s *auth.Session) {
	switch event {
	case auth.EventSignedIn, auth.EventTokenRefreshed:
		log.Printf("%s: session valid until %s", event, s.Expiry())
	case auth.EventSignedOut:
		log.Print("signed out")
	}
})
defer unsubscribe()

// GetSession returns the stored session (nil if none), refreshing it
// first when it is about to expire.
session, err := client.Auth.GetSession(ctx)
if err != nil {
	log.Fatal(err)
}
if session != nil {
	fmt.Println("access token expires at", session.Expiry())
}

// Sign out of the stored session ("" = use the stored session).
if err := client.Auth.SignOut(ctx, "", auth.SignOutLocal); err != nil {
	log.Print(err)
}
```

Methods that act for a user (`GetUser`, `UpdateUser`, `SignOut`,
`Reauthenticate`, identity methods, ...) take an access token right after
`ctx`: pass `""` to use the stored session, or a user's JWT to act for that
user without touching the stored session. You can also start and stop the
refresher yourself with `StartAutoRefresh(ctx)` / `StopAutoRefresh()`.

Operations on the stored session (sign-in, refresh, `UpdateUser`, MFA
verification, `SignOut`, ...) are serialized by one client-wide session
lock, like auth-js, so a refresh token is never used twice and a signed-out
session never comes back. Waiting for it honours `ctx` and
`auth.Config.LockAcquireTimeout` (default 10s; `auth.ErrLockAcquireTimeout`).
Token-rotating requests (refresh, MFA verify) complete and are stored even if
the caller's `ctx` is cancelled. Explicit-token and `NoStore` calls never
wait for the lock, and a `SessionStorage` must not call back into the client.

### Custom session storage

Implement [`auth.SessionStorage`](https://pkg.go.dev/github.com/lengzuo/supa/v2/auth#SessionStorage)
(`GetItem`, `SetItem`, `RemoveItem`; safe for concurrent use; `GetItem`
returns `""` and no error for a missing key) to persist the session and PKCE
verifiers somewhere other than memory. For example, a file-backed store for a
CLI:

```go
// fileStorage is an auth.SessionStorage that keeps the session and PKCE
// verifiers in files, so a CLI stays signed in across runs.
type fileStorage struct{ dir string }

func (s fileStorage) path(key string) string { return filepath.Join(s.dir, url.PathEscape(key)) }

func (s fileStorage) GetItem(_ context.Context, key string) (string, error) {
	b, err := os.ReadFile(s.path(key))
	if errors.Is(err, os.ErrNotExist) {
		return "", nil // absent keys return "" and no error
	}
	return string(b), err
}

func (s fileStorage) SetItem(_ context.Context, key, value string) error {
	return os.WriteFile(s.path(key), []byte(value), 0o600)
}

func (s fileStorage) RemoveItem(_ context.Context, key string) error {
	err := os.Remove(s.path(key))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}
```

```go
client, err := supabase.New(supabase.ProjectURL("your-project-ref"), os.Getenv("SUPABASE_PUBLISHABLE_KEY"), &supabase.Options{
	Auth: auth.Config{Storage: fileStorage{dir: os.TempDir()}},
})
```

### Multi-factor authentication

```go
// Enroll a TOTP factor for the signed-in user and show the QR code.
enrolled, err := client.Auth.MFA().Enroll(ctx, auth.MFAEnrollParams{
	FactorType:   auth.FactorTypeTOTP,
	FriendlyName: "Authenticator app",
})
if err != nil {
	log.Fatal(err)
}
fmt.Println("scan this QR code:", enrolled.TOTP.QRCode) // a data: URL; it is a secret

// Challenge the factor and verify the 6-digit code from the app.
challenge, err := client.Auth.MFA().Challenge(ctx, auth.MFAChallengeParams{FactorID: enrolled.ID})
if err != nil {
	log.Fatal(err)
}
session, err := client.Auth.MFA().Verify(ctx, auth.MFAVerifyParams{
	FactorID:    enrolled.ID,
	ChallengeID: challenge.ID,
	Code:        "123456",
})
if err != nil {
	log.Fatal(err)
}
fmt.Println("aal2 session until", session.Expiry())

// On a server acting for many users, use the caller's JWT instead:
//   client.Auth.MFA().WithAccessToken(jwt).ListFactors(ctx)
```

Also available: `ChallengeAndVerify`, `ListFactors`, `Unenroll`,
`GetAuthenticatorAssuranceLevel` and recovery codes (`MFA().RecoveryCodes()`).

### Admin API

The admin API needs a secret (`sb_secret_...`) or legacy `service_role` key.

```go
// Server only: a secret (sb_secret_...) or service_role key bypasses
// Row Level Security. Never ship it to browsers or mobile apps.
admin, err := supabase.New(supabase.ProjectURL("your-project-ref"), os.Getenv("SUPABASE_SECRET_KEY"), nil)
if err != nil {
	log.Fatal(err)
}

page, err := admin.Auth.Admin().ListUsers(ctx, &auth.AdminPageParams{Page: 1, PerPage: 50})
if err != nil {
	log.Fatal(err)
}
for _, u := range page.Users {
	fmt.Println(u.ID, u.Email)
}
fmt.Println("total users:", page.Total)

confirmed := true
user, err := admin.Auth.Admin().CreateUser(ctx, auth.AdminUserAttributes{
	Email:        "grace@example.com",
	Password:     "a-strong-password",
	EmailConfirm: &confirmed,
})
if err != nil {
	log.Fatal(err)
}

link, err := admin.Auth.Admin().GenerateLink(ctx, auth.AdminGenerateLinkParams{
	Type:       auth.AdminGenerateLinkTypeMagicLink,
	Email:      user.Email,
	RedirectTo: "https://example.com/welcome",
})
if err != nil {
	log.Fatal(err)
}
fmt.Println("magic link:", link.Properties.ActionLink)
```

Also available: `GetUserByID`, `UpdateUserByID`, `DeleteUser`,
`InviteUserByEmail`, `SignOut`, and the `MFA()`, `OAuth()`, `Passkey()` and
`CustomProviders()` admin APIs.

## Database

`client.From(table)` starts a PostgREST query. Builders are immutable values:
every method returns a new builder, so a partial query can be reused and
shared between goroutines. Run a query with `Execute` (raw
[`*postgrest.Response`](https://pkg.go.dev/github.com/lengzuo/supa/v2/postgrest#Response)),
`ExecuteInto(ctx, &dest)` or the generic `postgrest.ExecuteTo[T]`.

### Select, filter, order, paginate

```go
var todos []Todo
resp, err := client.From("todos").
	Select("id, title, done", postgrest.SelectOptions{Count: postgrest.CountExact}).
	Eq("done", false).
	ILike("title", "%milk%").
	In("priority", []int{1, 2}).
	Order("created_at", postgrest.OrderOptions{Descending: true}).
	Range(0, 9). // first page of 10 rows
	ExecuteInto(ctx, &todos)
if err != nil {
	log.Fatal(err)
}
fmt.Printf("%d of %d rows\n", len(todos), *resp.Count)
```

```go
// ExecuteTo is the generic form of ExecuteInto.
todos, _, err := postgrest.ExecuteTo[[]Todo](ctx, client.From("todos").Select("*").Limit(20))
if err != nil {
	log.Fatal(err)
}
```

All postgrest-js filters are there (`Neq`, `Gt`, `Gte`, `Lt`, `Lte`, `Like`,
`Is`, `NotIn`, `Contains`, `ContainedBy`, `Overlaps`, `TextSearch`, `Match`,
`Not`, `Or`, `Filter`, range operators, ...), plus modifiers such as `CSV`,
`GeoJSON`, `Explain`, `StripNulls`, `MaxAffected` and `Rollback`.

### Insert, upsert, update, delete

Mutations return no rows unless you chain `Select`.

```go
// Insert and return the inserted row (Select after a mutation asks for
// return=representation; without it nothing is returned).
var created []Todo
if _, err := client.From("todos").Insert(Todo{Title: "Buy milk"}).Select("*").ExecuteInto(ctx, &created); err != nil {
	log.Fatal(err)
}

// Upsert on a unique column.
_, err := client.From("todos").
	Upsert([]Todo{{ID: 1, Title: "Buy oat milk"}}, postgrest.UpsertOptions{OnConflict: "id"}).
	Execute(ctx)
if err != nil {
	log.Fatal(err)
}

// Update: always filter, or every row is updated.
var updated []Todo
_, err = client.From("todos").
	Update(map[string]any{"done": true}).
	Eq("id", created[0].ID).
	Select("*").
	ExecuteInto(ctx, &updated)
if err != nil {
	log.Fatal(err)
}

// Delete, counting the deleted rows.
resp, err := client.From("todos").
	Delete(postgrest.DeleteOptions{Count: postgrest.CountExact}).
	Eq("done", true).
	Execute(ctx)
if err != nil {
	log.Fatal(err)
}
fmt.Println("deleted", *resp.Count)
```

### Count only

```go
// Head: true returns only the count, no rows.
resp, err := client.From("todos").
	Select("*", postgrest.SelectOptions{Count: postgrest.CountExact, Head: true}).
	Eq("done", false).
	Execute(ctx)
if err != nil {
	log.Fatal(err)
}
fmt.Println("open todos:", *resp.Count)
```

### Single and MaybeSingle

```go
// Single fails (PGRST116) unless exactly one row matches.
var todo Todo
if _, err := client.From("todos").Select("*").Eq("id", 1).Single().ExecuteInto(ctx, &todo); err != nil {
	log.Fatal(err)
}

// MaybeSingle allows zero rows; use a pointer to tell "no row" apart.
maybe, _, err := postgrest.ExecuteTo[*Todo](ctx, client.From("todos").Select("*").Eq("id", 2).MaybeSingle())
if err != nil {
	log.Fatal(err)
}
if maybe == nil {
	fmt.Println("no todo 2")
}
```

### RPC (Postgres functions)

```go
// Calls the Postgres function add_todo(title text) returning setof todos.
var todos []Todo
_, err := client.RPC("add_todo", map[string]any{"title": "Write docs"}).
	Select("*").
	ExecuteInto(ctx, &todos)
if err != nil {
	log.Fatal(err)
}

// Read-only functions can be called with GET.
var total int
if _, err := client.RPC("count_todos", nil, postgrest.RPCOptions{Get: true}).ExecuteInto(ctx, &total); err != nil {
	log.Fatal(err)
}
```

### Other schemas

```go
// The schema must be exposed in the project's API settings.
var events []map[string]any
if _, err := client.Schema("analytics").From("events").Select("*").Limit(10).ExecuteInto(ctx, &events); err != nil {
	log.Fatal(err)
}
```

To use a non-`public` schema by default, set `Options.DB.Schema`.

### Querying as a specific user

`SetHeader` overrides the `Authorization` header for one query, so Row Level
Security runs as that user:

```go
// Run a query with a specific user's permissions (RLS applies).
http.HandleFunc("/api/todos", func(w http.ResponseWriter, r *http.Request) {
	jwt := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	var todos []Todo
	_, err := client.From("todos").
		Select("*").
		SetHeader("Authorization", "Bearer "+jwt).
		ExecuteInto(r.Context(), &todos)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	_ = json.NewEncoder(w).Encode(todos)
})
```

### Database errors

Every failure after a query is built is a
[`*postgrest.Error`](https://pkg.go.dev/github.com/lengzuo/supa/v2/postgrest#Error)
with the PostgREST/Postgres `Code`, `Message`, `Details`, `Hint` and HTTP
`Status` (0 for network errors, which unwrap to the cause, so
`errors.Is(err, context.DeadlineExceeded)` works).

```go
_, err := client.From("todos").Insert(Todo{Title: "dup"}).Execute(ctx)
var pgErr *postgrest.Error
if errors.As(err, &pgErr) {
	switch pgErr.Code {
	case "23505": // unique_violation
		log.Print("already exists: ", pgErr.Details)
	case "42501": // insufficient_privilege (RLS)
		log.Print("not allowed; hint: ", pgErr.Hint)
	default:
		log.Printf("postgrest: %s (HTTP %d)", pgErr.Message, pgErr.Status)
	}
}
```

GET and HEAD requests are retried on network errors and HTTP 503/520 by
default, like postgrest-js; see `postgrest.Config.Retry` and
`FilterBuilder.Retry`.

## Storage

### Buckets

```go
public := true
if _, err := client.Storage.CreateBucket(ctx, "avatars", &storage.BucketOptions{
	Public:           &public,
	FileSizeLimit:    "5MB",
	AllowedMIMETypes: []string{"image/*"},
}); err != nil && !storage.IsErrorCode(err, storage.CodeBucketAlreadyExists) {
	log.Fatal(err)
}

buckets, err := client.Storage.ListBuckets(ctx, nil)
if err != nil {
	log.Fatal(err)
}
for _, b := range buckets {
	fmt.Println(b.ID, b.Public)
}
```

### Files

```go
avatars := client.Storage.From("avatars")

// Upload streams any io.Reader (and closes it if it is an io.Closer).
f, err := os.Open("avatar.png")
if err != nil {
	log.Fatal(err)
}
up, err := avatars.Upload(ctx, "users/42/avatar.png", f, &storage.FileOptions{
	ContentType: "image/png",
	Upsert:      true,
})
if err != nil {
	log.Fatal(err)
}
fmt.Println("stored at", up.FullPath)

// Download as a stream; the caller closes it.
body, err := avatars.DownloadStream(ctx, "users/42/avatar.png", nil)
if err != nil {
	log.Fatal(err)
}
defer func() { _ = body.Close() }()
dst, err := os.Create("avatar-copy.png")
if err != nil {
	log.Fatal(err)
}
defer func() { _ = dst.Close() }()
if _, err := io.Copy(dst, body); err != nil {
	log.Fatal(err)
}

// A signed URL valid for one hour (private buckets).
signed, err := avatars.CreateSignedURL(ctx, "users/42/avatar.png", 3600, nil)
if err != nil {
	log.Fatal(err)
}

// A public URL (public buckets) with an image transformation. No request is made.
thumb := avatars.GetPublicURL("users/42/avatar.png", &storage.URLOptions{
	Transform: &storage.TransformOptions{Width: 128, Height: 128, Resize: storage.ResizeCover},
})
fmt.Println(signed, thumb)

// List a folder.
files, err := avatars.List(ctx, "users/42", &storage.ListFilesOptions{
	Limit:  100,
	SortBy: storage.SortBy{Column: "created_at", Order: "desc"},
})
if err != nil {
	log.Fatal(err)
}
for _, obj := range files {
	fmt.Println(obj.Name)
}
```

Also available: `Download` (into memory), `Update`, `Move`, `Copy`, `Remove`,
`Exists`, `Info`, `ListV2`, `CreateSignedURLs`, signed upload URLs
(`CreateSignedUploadURL` + `UploadToSignedURL`), object versions, bucket
lifecycle rules, and the analytics (`client.Storage.Analytics()`) and vector
(`client.Storage.Vectors()`) bucket APIs.

## Edge Functions

```go
type hello struct {
	Message string `json:"message"`
}
// Structs and maps are sent as JSON; the JSON reply is decoded into T.
reply, err := functions.InvokeJSON[hello](ctx, client.Functions, "hello", &functions.InvokeOptions{
	Body: map[string]string{"name": "Gopher"},
})
if err != nil {
	log.Fatal(err)
}
fmt.Println(reply.Message)
```

`Invoke` returns the response as a stream, which suits server-sent events and
large bodies. Always close it.

```go
resp, err := client.Functions.Invoke(ctx, "chat", &functions.InvokeOptions{
	Body:   map[string]string{"prompt": "Tell me a story"},
	Region: functions.RegionEuWest1, // run the function in a specific region
})
if err != nil {
	log.Fatal(err)
}
defer func() { _ = resp.Close() }()

// Read a text/event-stream (or any streamed body) line by line.
sc := bufio.NewScanner(resp.Body)
for sc.Scan() {
	fmt.Println(sc.Text())
}
if err := sc.Err(); err != nil {
	log.Fatal(err)
}
```

The request body is encoded by type: `string` as text, `[]byte` and
`io.Reader` as a stream, `url.Values` as a form, anything else as JSON. Set
`InvokeOptions.Method`, `Headers` or `Timeout` per call, or
`Options.Functions.Region` for a default region.

## Realtime

`client.Realtime` connects lazily on the first `Subscribe`. Register
callbacks on a channel before subscribing. Callbacks run one at a time on a
dedicated goroutine.

### Broadcast

```go
ch, err := client.Channel("room-1", realtime.ChannelOptions{
	Broadcast: realtime.BroadcastOptions{Self: true}, // also receive our own messages
})
if err != nil {
	log.Fatal(err)
}
type cursor struct{ X, Y int }
err = ch.OnBroadcast("cursor", func(m realtime.BroadcastMessage) {
	var c cursor
	if err := m.Decode(&c); err == nil {
		log.Printf("cursor at %d,%d", c.X, c.Y)
	}
})
if err != nil {
	log.Fatal(err)
}
if err := ch.Subscribe(ctx); err != nil {
	log.Fatal(err)
}
if err := ch.Send(ctx, realtime.SendParams{Event: "cursor", Payload: cursor{X: 10, Y: 20}}); err != nil {
	log.Fatal(err)
}
```

`ch.HTTPSend(ctx, event, payload)` broadcasts over REST without a websocket.

### Presence

```go
ch, err := client.Channel("lobby", realtime.ChannelOptions{
	Presence: realtime.PresenceOptions{Key: "user-42"},
})
if err != nil {
	log.Fatal(err)
}
// Presence callbacks must be registered before Subscribe.
if err := ch.OnPresenceSync(func() {
	log.Printf("%d users online", len(ch.PresenceState()))
}); err != nil {
	log.Fatal(err)
}
if err := ch.OnPresenceJoin(func(e realtime.PresenceJoinEvent) {
	log.Print("joined: ", e.Key)
}); err != nil {
	log.Fatal(err)
}
if err := ch.Subscribe(ctx); err != nil {
	log.Fatal(err)
}
if err := ch.Track(ctx, map[string]any{"online_at": time.Now()}); err != nil {
	log.Fatal(err)
}
```

### Postgres changes

```go
filter, err := realtime.NewPostgresFilter().Eq("room_id", 1).Build() // "room_id=eq.1"
if err != nil {
	log.Fatal(err)
}
ch, err := client.Channel("room-1-messages", realtime.ChannelOptions{})
if err != nil {
	log.Fatal(err)
}
err = ch.OnPostgresChanges(realtime.PostgresChangesFilter{
	Event:  realtime.PostgresChangeInsert,
	Schema: "public",
	Table:  "messages",
	Filter: filter,
}, func(p realtime.PostgresChangesPayload) {
	var m Message
	if err := p.DecodeNew(&m); err == nil {
		log.Printf("new message %d: %s", m.ID, m.Body)
	}
})
if err != nil {
	log.Fatal(err)
}
if err := ch.Subscribe(ctx); err != nil {
	log.Fatal(err)
}
```

The table must be in the `supabase_realtime` publication, and RLS decides
which rows each subscriber receives.

### Tokens and shutting down

```go
// The Auth session's token is synced to Realtime automatically. Set a
// token yourself when you manage tokens outside client.Auth:
if err := client.Realtime.SetAuth(ctx, "user-access-token"); err != nil {
	log.Fatal(err)
}

// Leave one channel, or all of them.
if err := client.RemoveChannel(ctx, ch); err != nil {
	log.Print(err)
}
if err := client.RemoveAllChannels(ctx); err != nil {
	log.Print(err)
}
// Close the websocket (channels rejoin on the next Subscribe) ...
if err := client.Realtime.Disconnect(ctx); err != nil {
	log.Print(err)
}
// ... or shut the whole client down.
if err := client.Close(ctx); err != nil {
	log.Print(err)
}
```

## Third-party auth

With Clerk, Auth0, Firebase Auth, AWS Cognito or another
[third-party auth provider](https://supabase.com/docs/guides/auth/third-party/overview),
give the client a function that returns the provider's token. Every service
sends it, and `client.Auth` is disabled.

```go
// Third-party auth (Clerk, Auth0, Firebase, Cognito, ...): every service
// sends the token returned by AccessToken. client.Auth is nil.
client, err := supabase.New(supabase.ProjectURL("your-project-ref"), os.Getenv("SUPABASE_PUBLISHABLE_KEY"), &supabase.Options{
	AccessToken: func(ctx context.Context) (string, error) {
		return tokenFromYourIdentityProvider(ctx)
	},
})
if err != nil {
	log.Fatal(err)
}
if _, err := client.AuthClient(); errors.Is(err, supabase.ErrAuthDisabled) {
	fmt.Println("Auth is managed by the third-party provider")
}
```

## HTTP client, headers and logging

```go
client, err := supabase.New(supabase.ProjectURL("your-project-ref"), os.Getenv("SUPABASE_PUBLISHABLE_KEY"), &supabase.Options{
	// Used by every service: proxies, mTLS, instrumented transports.
	HTTPClient: &http.Client{Transport: &http.Transport{Proxy: http.ProxyFromEnvironment}},
	// Sent with every request to every service.
	Headers: http.Header{"X-App-Version": {"1.4.2"}},
	// Redacted debug logs from every service.
	Logger: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})),
	// Per-service settings.
	DB: postgrest.Config{Schema: "api", Timeout: 10 * time.Second},
})
```

`Options.Auth`, `DB`, `Storage`, `Functions` and `Realtime` hold the
per-service configs. A service's own `HTTPClient` or `Logger` replaces the
global one, its `Headers` are merged over the global headers, and its
`RequestEditors` run after the global editors. Avoid
`http.Client.Timeout` on a shared client: it also cuts off streamed function
responses and downloads. Bound calls with `ctx`, or use the per-service
`Timeout` settings.

## Tracing

`supabase.PropagateTrace` turns an injector into a request editor that adds
`traceparent` (and, for sampled traces, `tracestate` and `baggage`) to
Supabase requests only, following the supabase-js rules. With OpenTelemetry:

```go
// Requires these imports in your module (not dependencies of this SDK):
//   "go.opentelemetry.io/otel"
//   "go.opentelemetry.io/otel/propagation"
client, err := supabase.New(supabase.ProjectURL("your-project-ref"), os.Getenv("SUPABASE_PUBLISHABLE_KEY"), &supabase.Options{
	RequestEditors: []func(*http.Request) error{
		supabase.PropagateTrace(func(r *http.Request) {
			otel.GetTextMapPropagator().Inject(r.Context(), propagation.HeaderCarrier(r.Header))
		}),
	},
})
```

This snippet is not compiled in this repository because the SDK does not
depend on OpenTelemetry; `ExamplePropagateTrace` in
[`v2/example_test.go`](v2/example_test.go) shows the same wiring with a
standard-library injector. For client spans, set `Options.HTTPClient` to a
client with an instrumented transport such as `otelhttp.NewTransport`.

## Server-side usage and security

- **Never ship a secret key to clients.** Secret (`sb_secret_...`) and legacy
  `service_role` keys bypass Row Level Security and unlock the admin API. Use
  them only in trusted server code, from an environment variable or secret
  manager. Browsers, mobile apps and CLIs you distribute get the publishable
  (or anon) key.
- **The default client keeps one session.** `client.Auth` stores a single
  current session and `From`, `Storage`, `Functions` and `Realtime` send its
  token. On a server that serves many users, never sign users in on a shared
  client: every request would then run as whoever signed in last. Instead:
  - verify each request's JWT with `client.Auth.GetUser(ctx, jwt)` or
    `GetClaims`, and pass the JWT per call (`SetHeader("Authorization",
    "Bearer "+jwt)` on queries, the `accessToken` argument of Auth methods,
    `MFA().WithAccessToken(jwt)`, `InvokeOptions.Headers` for functions), or
  - create a client per request bound to the caller's JWT:

    ```go
    // One client per request, bound to the caller's JWT: Database, Storage,
    // Functions and Realtime all act as that user.
    http.HandleFunc("/api/upload", func(w http.ResponseWriter, r *http.Request) {
    	jwt := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
    	userClient, err := supabase.New(supabase.ProjectURL("your-project-ref"), os.Getenv("SUPABASE_PUBLISHABLE_KEY"), &supabase.Options{
    		AccessToken: func(context.Context) (string, error) { return jwt, nil },
    	})
    	if err != nil {
    		http.Error(w, err.Error(), http.StatusInternalServerError)
    		return
    	}
    	_, err = userClient.Storage.From("uploads").Upload(r.Context(), "incoming/file.bin", r.Body, &storage.FileOptions{
    		ContentType: r.Header.Get("Content-Type"),
    	})
    	if err != nil {
    		http.Error(w, err.Error(), http.StatusBadGateway)
    	}
    })
    ```

  - Avoid `client.Functions.SetAuth` on a shared client: it changes the token
    for every later invocation from every goroutine.
- **RLS applies to user tokens.** Requests made with a user's JWT (or with the
  publishable key and no user) are filtered by your Row Level Security
  policies. Requests made with a secret key are not, so check authorization
  yourself before using one on a user's behalf.
- **Authenticate with the server, not the session.** `GetSession` returns
  what is in storage without verifying it; use `GetUser` or `GetClaims` to
  authenticate requests.
- `Options.Logger` receives redacted debug logs; still treat debug logs as
  sensitive and keep them out of shared sinks in production.

## Error handling

Every service returns typed errors; inspect them with `errors.As`.

| Package | Error type | What to look at |
|---|---|---|
| `auth` | `*auth.Error` | `Code` (`auth.ErrorCodeInvalidCredentials`, `ErrorCodeEmailNotConfirmed`, `ErrorCodeWeakPassword`, `ErrorCodeOverRequestRateLimit`, ...), `StatusCode`, `Retryable`, `WeakPasswordReasons`. Sentinels such as `auth.ErrSessionMissing` match with `errors.Is`. |
| `postgrest` | `*postgrest.Error` | `Code` (Postgres SQLSTATE such as `23505`, or PostgREST `PGRST116`), `Message`, `Details`, `Hint`, `Status`. |
| `storage` | `*storage.Error` | `Code` (`storage.CodeNoSuchKey`, `CodeAccessDenied`, `CodeResourceAlreadyExists`, ...), `Status`, `Message`; or `storage.IsErrorCode(err, code)`. |
| `functions` | `*functions.HTTPError`, `*functions.RelayError`, `*functions.FetchError` | Non-2xx from the function (`StatusCode`, `Body`, `DecodeJSON`); relay failure; transport failure (`Err`, unwraps to context errors). |
| `realtime` | `*realtime.SubscribeError`, `*realtime.PushError`, `*realtime.HTTPError` | `errors.Is(err, realtime.ErrTimedOut)` and friends. |

```go
_, err = client.SignInWithPassword(ctx, auth.SignInWithPasswordParams{Email: "ada@example.com", Password: "wrong"})
var authErr *auth.Error
if errors.As(err, &authErr) {
	switch authErr.Code {
	case auth.ErrorCodeInvalidCredentials:
		log.Print("wrong email or password")
	case auth.ErrorCodeEmailNotConfirmed:
		log.Print("confirm your email first")
	case auth.ErrorCodeOverRequestRateLimit:
		log.Print("slow down")
	default:
		log.Printf("auth error %d %s: %s (retryable: %t)",
			authErr.StatusCode, authErr.Code, authErr.Message, authErr.Retryable)
	}
}
// Sentinel errors match by code.
if errors.Is(err, auth.ErrSessionMissing) {
	log.Print("not signed in")
}
```

```go
_, err = client.From("avatars").Download(ctx, "missing.png", nil)
var stErr *storage.Error
switch {
case storage.IsErrorCode(err, storage.CodeNoSuchKey):
	log.Print("no such object")
case storage.IsErrorCode(err, storage.CodeAccessDenied):
	log.Print("denied by a storage RLS policy")
case errors.As(err, &stErr):
	log.Printf("storage error %d %s: %s", stErr.Status, stErr.Code, stErr.Message)
}
```

```go
_, err = functions.InvokeJSON[map[string]any](ctx, client, "hello", nil)
var (
	httpErr  *functions.HTTPError
	relayErr *functions.RelayError
	fetchErr *functions.FetchError
)
switch {
case errors.As(err, &httpErr): // the function returned a non-2xx status
	var body struct {
		Error string `json:"error"`
	}
	if httpErr.DecodeJSON(&body) == nil {
		log.Printf("function failed with %d: %s", httpErr.StatusCode, body.Error)
	}
case errors.As(err, &relayErr): // Supabase could not invoke the function
	log.Printf("relay error %d", relayErr.StatusCode)
case errors.As(err, &fetchErr): // network failure, timeout or cancellation
	log.Print("request failed: ", fetchErr.Err)
}
```

(In these three snippets `client` is the standalone `auth`, `storage` and
`functions` client respectively, as in each package's `example_test.go`; with
a `*supabase.Client` use `client.Auth`, `client.Storage` and
`client.Functions`.) See [Database errors](#database-errors) for
`*postgrest.Error`.

## Feature parity

[`v2/compliance/`](v2/compliance/) maps every feature of the canonical
Supabase client capability matrix (the `sdk-compliance.yaml` published by
supabase-js, 251 features listed in
[`upstream_features.txt`](v2/compliance/upstream_features.txt)) to the Go
symbols and tests that implement it, one YAML file per area (`client`,
`auth-core`, `auth-mfa`, `auth-admin`, `database`, `storage-files`,
`storage-analytics-vectors`, `functions`, `realtime`). `TestCompliance` fails
if a feature is unmapped or mapped twice, or if a listed symbol or test does
not exist:

```sh
cd v2
go test ./compliance/
```

250 features are `implemented`. One is `not_applicable`:

- `auth.session.sign_out_reason`: upstream marks it not implemented, auth-js
  exposes no sign-out reason (`SIGNED_OUT` carries only a null session), and
  the Auth API's `POST /logout` returns none, so there is nothing to surface.

## Migrating from v1

v1 (`github.com/lengzuo/supa`, the package at the repository root) is
superseded by v2. v2 is a new module, so both can live side by side while you
migrate.

1. **Module path.** `go get github.com/lengzuo/supa/v2` and import
   `supabase "github.com/lengzuo/supa/v2"`. The package name is still
   `supabase`.
2. **Package layout.** v1 was a single package. v2 splits services into
   `auth`, `postgrest`, `storage`, `functions` and `realtime`; request and
   response types live in those packages (`auth.SignInWithPasswordParams`,
   `storage.FileOptions`, ...). Edge Functions and Realtime are new.
3. **Renamed and reshaped APIs:**

| v1 | v2 |
|---|---|
| `supabase.New(supabase.Config{ApiKey: key, ProjectRef: ref})` | `supabase.New(supabase.ProjectURL(ref), key, nil)` (any URL works, including self-hosted and local) |
| `Config.Debug` | `Options.Logger` (`*slog.Logger`) |
| `Config.AuthOptions` / `PostgresOptions` / `StorageOptions` with `WithAuthClient(...)` etc. | `Options.HTTPClient`, `Options.Headers`, and per-service `Options.Auth` / `DB` / `Storage` |
| `client.DB.From("t").Select("*").Execute(ctx, &out)` | `client.From("t").Select("*").ExecuteInto(ctx, &out)` (or `postgrest.ExecuteTo[T]`) |
| `client.DB.From("t", supabase.AuthToken(jwt))` | `client.From("t").Select("*").SetHeader("Authorization", "Bearer "+jwt)` |
| `client.DB.RPC(fn, params).Execute(ctx, &out)` | `client.RPC(fn, args).ExecuteInto(ctx, &out)` |
| Filters taking `string` values; `Ilike`, `Fts`/`Plfts`/`Wfts`, `Cs`/`Cd`/`Ov`, `Sl`/`Sr`/`Nxl`/`Nxr`/`Ad` | Filters taking `any`; `ILike`, `TextSearch` with `TextSearchOptions`, `Contains`/`ContainedBy`/`Overlaps`, `RangeLt`/`RangeGt`/`RangeGte`/`RangeLte`/`RangeAdjacent` |
| `Order(column, supabase.OrderDesc)` | `Order(column, postgrest.OrderOptions{Descending: true})` |
| `client.Auth.SignInWithPassword(ctx, supabase.SignInRequest{...})` | `client.Auth.SignInWithPassword(ctx, auth.SignInWithPasswordParams{...})` |
| `client.Auth.SignUp(ctx, supabase.SignUpRequest{...})` | `client.Auth.SignUp(ctx, auth.SignUpParams{...})` |
| `client.Auth.SignInWithOTP(ctx, supabase.SignInRequest{...})` | `client.Auth.SignInWithOTP(ctx, auth.SignInWithOTPParams{...})` |
| `client.Auth.Verify(ctx, supabase.VerifyRequest{...})` | `client.Auth.VerifyOTP(ctx, auth.VerifyOTPParams{...})` |
| `client.Auth.User(ctx, token)` | `client.Auth.GetUser(ctx, jwt)` |
| `client.Auth.RefreshToken(ctx, refreshToken)` | `client.Auth.RefreshSession(ctx, refreshToken)` |
| `client.Auth.SignOut(ctx, token)` | `client.Auth.SignOut(ctx, token, auth.SignOutGlobal)` |
| `client.Auth.SignInWithOAuth(ctx, req)` returning a URL string | `client.Auth.SignInWithOAuth(ctx, auth.SignInWithOAuthParams{...})` returning `*auth.OAuthResponse` (`.URL`) |
| `*supabase.AuthDetailResp` | `*auth.AuthResponse` (`User`, `Session`) |
| `client.Storage.UploadFile(ctx, path, mimeType, r)` with `Config.Bucket` | `client.Storage.From(bucket).Upload(ctx, path, r, &storage.FileOptions{ContentType: mimeType})` |
| `client.Storage.GetPublicUrl(path)` | `client.Storage.From(bucket).GetPublicURL(path, nil)` |
| `supabase.Exception`, `*supabase.PostgresError` | `*auth.Error`, `*storage.Error`, `*postgrest.Error` (see [Error handling](#error-handling)) |

Behavior changes worth knowing: v2 builders are immutable and safe to share;
mutations return no rows unless you chain `Select`; the Auth client can keep a
session (in v1 you always passed tokens yourself), so on servers follow
[Server-side usage and security](#server-side-usage-and-security).

## Development

The v2 module lives in [`v2/`](v2/). From there:

```sh
cd v2
gofmt -l .                     # must print nothing
go vet ./...
go test -race ./...            # unit tests use httptest; no Supabase project needed
go test ./compliance/          # feature-parity check against the upstream matrix
golangci-lint run ./...
```

Examples (`example_test.go` files) are compiled by `go test`, so the README
snippets cannot drift from the API. Contributor and agent guidelines are in
[AGENTS.md](AGENTS.md).

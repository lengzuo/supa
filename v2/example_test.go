package supabase_test

// These examples back every code snippet in the repository README. They are
// compiled by `go test` but never run (they have no Output comment), so they
// make no network requests.

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	supabase "github.com/lengzuo/supa/v2"
	"github.com/lengzuo/supa/v2/auth"
	"github.com/lengzuo/supa/v2/functions"
	"github.com/lengzuo/supa/v2/postgrest"
	"github.com/lengzuo/supa/v2/realtime"
	"github.com/lengzuo/supa/v2/storage"
)

type Todo struct {
	ID    int64  `json:"id,omitempty"`
	Title string `json:"title"`
	Done  bool   `json:"done"`
}

type Message struct {
	ID     int64  `json:"id"`
	RoomID int64  `json:"room_id"`
	Body   string `json:"body"`
}

// exampleClient stands in for the client created in Example.
func exampleClient() *supabase.Client {
	client, err := supabase.New(supabase.ProjectURL("your-project-ref"), os.Getenv("SUPABASE_PUBLISHABLE_KEY"), nil)
	if err != nil {
		log.Fatal(err)
	}
	return client
}

// ---------------------------------------------------------------------------
// Quick start

func Example() {
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
}

func ExampleNew_selfHosted() {
	// Local development (`supabase start`) or a self-hosted instance:
	// pass the API gateway URL instead of ProjectURL.
	client, err := supabase.New("http://127.0.0.1:54321", os.Getenv("SUPABASE_PUBLISHABLE_KEY"), nil)
	if err != nil {
		log.Fatal(err)
	}
	_ = client
}

func ExampleNew_options() {
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
	if err != nil {
		log.Fatal(err)
	}
	_ = client
}

// ---------------------------------------------------------------------------
// Auth

func ExampleClient_signUp() {
	ctx := context.Background()
	client := exampleClient()

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
}

func ExampleClient_signInWithPassword() {
	ctx := context.Background()
	client := exampleClient()

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
}

func ExampleClient_signInWithOTP() {
	ctx := context.Background()
	client := exampleClient()

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
}

func ExampleClient_oauthPKCE() {
	ctx := context.Background()

	// PKCE keeps the code verifier in the client's SessionStorage between
	// the redirect and the callback.
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
}

func ExampleClient_getUser() {
	client := exampleClient()

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
}

func ExampleClient_sessions() {
	ctx := context.Background()

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
}

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

func ExampleClient_sessionStorage() {
	client, err := supabase.New(supabase.ProjectURL("your-project-ref"), os.Getenv("SUPABASE_PUBLISHABLE_KEY"), &supabase.Options{
		Auth: auth.Config{Storage: fileStorage{dir: os.TempDir()}},
	})
	if err != nil {
		log.Fatal(err)
	}
	_ = client
}

func ExampleClient_mfa() {
	ctx := context.Background()
	client := exampleClient()

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
}

func ExampleClient_admin() {
	ctx := context.Background()

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
}

// ---------------------------------------------------------------------------
// Database

func ExampleClient_From() {
	ctx := context.Background()
	client := exampleClient()

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
}

func ExampleClient_From_executeTo() {
	ctx := context.Background()
	client := exampleClient()

	// ExecuteTo is the generic form of ExecuteInto.
	todos, _, err := postgrest.ExecuteTo[[]Todo](ctx, client.From("todos").Select("*").Limit(20))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(len(todos))
}

func ExampleClient_From_mutations() {
	ctx := context.Background()
	client := exampleClient()

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
}

func ExampleClient_From_count() {
	ctx := context.Background()
	client := exampleClient()

	// Head: true returns only the count, no rows.
	resp, err := client.From("todos").
		Select("*", postgrest.SelectOptions{Count: postgrest.CountExact, Head: true}).
		Eq("done", false).
		Execute(ctx)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("open todos:", *resp.Count)
}

func ExampleClient_From_single() {
	ctx := context.Background()
	client := exampleClient()

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
}

func ExampleClient_RPC() {
	ctx := context.Background()
	client := exampleClient()

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
	fmt.Println(total)
}

func ExampleClient_Schema() {
	ctx := context.Background()
	client := exampleClient()

	// The schema must be exposed in the project's API settings.
	var events []map[string]any
	if _, err := client.Schema("analytics").From("events").Select("*").Limit(10).ExecuteInto(ctx, &events); err != nil {
		log.Fatal(err)
	}
}

func ExampleClient_From_userToken() {
	client := exampleClient()

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
}

func ExampleClient_From_errors() {
	ctx := context.Background()
	client := exampleClient()

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
}

// ---------------------------------------------------------------------------
// Storage

func ExampleClient_storageBuckets() {
	ctx := context.Background()
	client := exampleClient()

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
}

func ExampleClient_storageFiles() {
	ctx := context.Background()
	client := exampleClient()
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
}

// ---------------------------------------------------------------------------
// Edge Functions

func ExampleClient_functions() {
	ctx := context.Background()
	client := exampleClient()

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
}

func ExampleClient_functionsStreaming() {
	ctx := context.Background()
	client := exampleClient()

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
}

// ---------------------------------------------------------------------------
// Realtime

func ExampleClient_Channel_broadcast() {
	ctx := context.Background()
	client := exampleClient()

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
}

func ExampleClient_Channel_presence() {
	ctx := context.Background()
	client := exampleClient()

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
}

func ExampleClient_Channel_postgresChanges() {
	ctx := context.Background()
	client := exampleClient()

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
}

func ExampleClient_Channel_lifecycle() {
	ctx := context.Background()
	client := exampleClient()
	ch, err := client.Channel("room-1", realtime.ChannelOptions{})
	if err != nil {
		log.Fatal(err)
	}

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
}

// ---------------------------------------------------------------------------
// Third-party auth, server-side usage, tracing

func ExampleOptions_accessToken() {
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
}

func tokenFromYourIdentityProvider(context.Context) (string, error) { return "", nil }

func ExampleOptions_perRequest() {
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
}

func ExamplePropagateTrace() {
	// inject copies the current trace context into r.Header. With
	// OpenTelemetry it is otel.GetTextMapPropagator().Inject(...); see the README.
	inject := func(r *http.Request) {
		if tp, ok := r.Context().Value(traceparentKey{}).(string); ok {
			r.Header.Set("traceparent", tp)
		}
	}
	client, err := supabase.New(supabase.ProjectURL("your-project-ref"), os.Getenv("SUPABASE_PUBLISHABLE_KEY"), &supabase.Options{
		RequestEditors: []func(*http.Request) error{supabase.PropagateTrace(inject)},
	})
	if err != nil {
		log.Fatal(err)
	}
	_ = client
}

type traceparentKey struct{}

# AGENTS.md

Guidance for AI coding agents (and humans) working on `github.com/lengzuo/supa`.

## Role

Work as a **staff software engineer who has spent decades building public Go
libraries and tools**. That means:

- **The public API is a contract.** Every exported identifier is a promise to
  strangers you will never meet. Do not rename, remove, or change the signature
  or behavior of an exported symbol without saying so plainly and giving a
  migration path. When in doubt, add something new and deprecate the old one
  with a `// Deprecated:` comment.
- **Correctness over cleverness.** Plain, boring, idiomatic Go. Follow
  [Effective Go](https://go.dev/doc/effective_go),
  [Go Code Review Comments](https://go.dev/wiki/CodeReviewComments) and the
  [Google Go style guide](https://google.github.io/styleguide/go/).
- **Secure by default.** This library handles API keys, user access tokens,
  refresh tokens and passwords. Treat every change as security-relevant.
- **Safe under concurrency.** Users will share one `*Client` across goroutines.
  Anything reachable from `Client` must be safe for concurrent use.
- **Few dependencies.** Each new module is a cost to every downstream user.
  Prefer the standard library. Justify any new dependency in the PR.
- **Small, reviewable changes.** One concern per PR. Do not bundle unrelated
  refactors with a fix.
- **Push back.** If a request would break users, leak secrets, or add a
  footgun, say so and propose a better design before writing code.

## Project overview

`supa` is a Go client SDK for [Supabase](https://supabase.com). It is one
package at the repo root:

- Module path: `github.com/lengzuo/supa`
- Package name: **`supabase`**. This differs from the import path, so users
  write `supabase.New(...)`.
- Minimum Go version: **1.20** (`go.mod`). Do not use newer language
  features or stdlib APIs: no builtin `min`/`max`/`clear` (Go 1.21), no
  `slices`/`maps` stdlib packages (Go 1.21), no range-over-int or range-over-func
  (Go 1.22/1.23), and no `log/slog`. The local toolchain may be newer, so
  keep code that compiles on 1.20.

### File map

| File | Responsibility |
|---|---|
| `client.go` | `New(Config)` wires Auth, DB and Storage. `defaultSender` builds the default `*http.Client`. Holds shared constants (`/auth/v1`, `/storage/v1`, the `apiKey` header). |
| `config.go` | Public `Config` struct (API key, project ref, bucket, debug, per-service options). |
| `http_client.go` | `Sender` interface and the `requester` implementation (`Call` for JSON, `Upload` for streams). Every network request goes through this file. |
| `http_options.go` | `HTTPOption` / `clientConfig`. Currently unused scaffolding. |
| `auth.go` | GoTrue (Supabase Auth) API: sign-up, sign-in (password/OTP/OAuth/ID token/anonymous), verify, refresh, user, update, sign-out. Exposed through the unexported `authAPI` interface. |
| `postgres.go`, `postgres_options.go` | PostgREST client (`PostgresClient`, `PostgresAPI`), per-request `HeaderOption` / `AuthToken`, client options. |
| `postgres_request_builder.go` | `From(table)` → `Select/Insert/Upsert/Update/Delete`, and `QueryRequestBuilder.Execute`. |
| `postgres_filter_builder.go` | PostgREST filters (`Eq`, `Gt`, `In`, `Not`, `Single`, …). |
| `postgres_select_builder.go` | `Order`, `Range`, `Limit`, `Offset`. |
| `postgres_rpc_builder.go` | `RPC(fn, params)` and its `Execute`. |
| `storage.go` | Storage API: `UploadFile`, `GetPublicUrl`. |
| `dto.go` | Request/response structs. `json` tags set the body; `url` tags set the query string. |
| `enums.go` | `Header`, `VerifyType`, `Order`, `Provider` enums with `String()`. |
| `err.go` | `Exception` interface, `External(...)` for non-2xx auth/storage responses, `PostgresError` for PostgREST errors, `ErrEmptyApiKey`. |
| `logger.go` | Package-global zerolog wrapper, enabled by `Config.Debug`. |
| `query.go` | **Vendored copy of `google/go-querystring`** (BSD). Keep its copyright header. Only change it to fix a bug, and note that it was changed. |
| `common.go` | `apiHostFormat`, generic `min`, the `Resp` and `StreamResp` types. |

### Upstream references

Keep behavior aligned with the official clients. Read them before adding an
endpoint:

- Auth: `supabase/auth-js` (formerly gotrue-js), `GoTrueClient.ts`, `GoTrueAdminApi.ts`
- Database: `supabase/postgrest-js` (`PostgrestClient.ts`, `PostgrestFilterBuilder.ts`, `PostgrestTransformBuilder.ts`)
- Storage: `supabase/storage-js`
- PostgREST docs: <https://postgrest.org/en/stable/references/api.html>

## Conventions already in the codebase

Follow these unless you are deliberately fixing them. If so, fix them in a
separate PR.

- **Service constructors and functional options:** `NewAuth(apiKey, host, ...AuthOption)`,
  `NewStorage(...)`, `NewPostgres(projectRef, ...PostgresOption)`. Options are
  `func(*T)`. New configuration should be a new `WithXxx` option, not a new
  positional parameter.
- **Adding an auth/storage endpoint** follows this shape:
  1. Add request/response structs to `dto.go` with explicit `json:"..."` and
     `url:"..."` tags. Use `url:"-"` on anything that must not appear in the
     query string. `requester.Call` runs `Values(body)` on every body, so a
     field without a `url` tag **will be put in the URL**.
  2. Add the method to the `authAPI` / `storageAPI` interface **and** the
     concrete type (value receiver `func (i Auth)` for Auth, pointer receiver
     for Storage, to match the existing code).
  3. Call `i.httpClient.Call(ctx, url, method, body, headerSetter)`. Always set
     the `apiKey` header, and `Authorization: Bearer <token>` when the call is
     made on behalf of a user.
  4. On a transport error, return `err`. On a non-2xx status, return
     `External(body, status)`. On success, unmarshal into the DTO.
- **Postgres builders** return pointers and chain. Filters are appended to
  `url.Values`. `Execute(ctx, result)` unmarshals into `result`. `result == nil`
  means "no body wanted" and clears the `Accept`/`Prefer` headers.
- **Errors:** auth and storage return `Exception` (use `errors.As` to get the
  status code). Postgres and RPC return `*PostgresError`. Keep these types
  stable. They are part of the public API.
- **Context:** every network-facing method takes `ctx context.Context` as its
  first parameter and must pass it to `http.NewRequestWithContext`.
- **Logging:** use the package `logger` (`Debug`/`Warn`/`Error`, printf-style).
  Logging is off unless `Config.Debug` is true. Never use `fmt.Print*` or the
  `log` package in library code.
- **Doc comments** on every exported identifier, starting with the identifier's
  name (`// SignUp creates a new user.`).

## Known hazards: read before touching the HTTP layer

These are real issues in the current code. Do not copy the patterns into new
code. Fix them in focused PRs, with tests.

1. **The header map is shared across requests (data race and credential leak).**
   `requester.Call`/`Upload` do `httpReq.Header = c.customHeader` and then
   mutate it. Every request writes into the same `http.Header`, so a user's
   `Authorization` token from one call can be sent on another concurrent call.
   The fix is to `Clone()` the header per request. Any change here needs a
   `-race` test that runs concurrent calls with different tokens.
2. **Secrets in debug logs.** `Call` logs full request headers (the API key and
   bearer tokens) and the first 500 bytes of bodies (passwords, refresh
   tokens). New code must not log secrets. Redact `Authorization`, `apiKey`,
   and token/password fields.
3. **Global logger.** `newLogger` replaces a package-level variable on every
   `New(...)`, so two clients with different `Debug` settings step on each
   other. Before calling `New`, `logger` is nil. Code paths that can run
   before `New` must not log.
4. **Builders mutate shared state.** `RequestBuilder.Insert/Upsert/Update` set
   headers on `b.header`, and filters mutate `params` in place. Builders are
   single-use and not goroutine-safe. Document this, or copy on write.
5. **Enum `String()` indexes an array** and panics for out-of-range values.
   New enums should use a `switch` with a fallback.
6. **`NewPostgres` panics** on a bad URL. New constructors should return an
   error instead.
7. **Hard-coded host** `https://%s.supabase.co`. Self-hosted and local
   (`supabase start`) setups are not supported yet. A `WithBaseURL`-style
   option is the backward-compatible way to add them.
8. **Filter values are not escaped.** `In`/`Cs`/`Cd`/`Ov` join raw strings.
   Values that contain `,`, `(`, `)` or `"` change the PostgREST query.
   postgrest-js quotes such values. Follow that when fixing it.
9. **README drift.** The README shows `dto.` and `enum.` packages and
   `ExecuteWithContext`, but none of these exist. The real names are
   `supabase.SignUpRequest`, `supabase.VerifyTypeMagicLink.String()` and
   `Execute`. When you change the API, update the README examples in the same PR.

## Commands

```sh
go build ./...
go vet ./...
gofmt -l .                  # must print nothing
go test -race ./...         # there are no tests yet; add them
golangci-lint run ./...     # 9 existing findings (errcheck/staticcheck/unused); add no new ones
go mod tidy                 # go.mod/go.sum must stay tidy
```

Before you call a change done, all of the above must pass. To check the Go
1.20 floor, run `GOTOOLCHAIN=go1.20.14 go build ./...` when network access
allows.

## Testing standards

- There are no tests yet. **Every bug fix or new feature adds tests.** Use the
  standard `testing` package with table-driven tests. `testify` is already a
  dependency (`assert`/`require`) and is fine to use.
- **Never hit a real Supabase project in unit tests.** Use
  `net/http/httptest.NewServer` and point clients at it. For Auth/Storage, pass
  the server URL as the host (`NewAuth(key, srv.URL+"/auth/v1")`). For
  Postgres, there is no base-URL option yet, so write an internal test
  (`package supabase`) that sets `baseURL` on the `PostgresClient` returned by
  `NewPostgres` to point at the test server.
- Assert on the **wire format**: method, path, query string, headers
  (`apiKey`, `Authorization`, `Prefer`, `Accept`) and JSON body. That is the
  contract with Supabase.
- Cover error paths: non-2xx with a JSON error body, non-2xx with a non-JSON
  body, transport errors, context cancellation.
- Run with `-race`. Anything that touches `requester` or the builders needs a
  concurrent test.
- Integration tests against a live project go behind a build tag
  (`//go:build integration`) and read credentials from env vars. `tests/` is
  git-ignored for local scratch work. Never commit keys.

## API design checklist for public changes

- [ ] Is the new exported name the smallest surface that solves the problem?
      Could it stay unexported?
- [ ] Does it take `context.Context` first and return `error` last?
- [ ] Can it be configured with an option instead of a breaking signature
      change?
- [ ] Is it safe for concurrent use, or clearly documented as not?
- [ ] Are errors inspectable (`errors.As`/`errors.Is`) and wrapped with `%w`
      where you add context?
- [ ] Does anything log or return a secret?
- [ ] Does it compile on Go 1.20?
- [ ] Doc comment, README example, and tests updated?
- [ ] Is a breaking change unavoidable? Then call it out explicitly in the PR
      and in the release notes (the module is v0, but users still depend on it).

## Git and PR hygiene

- Commit style in history: short imperative summaries, often prefixed
  (`add:`, `fix:`, `refactor:`, `change:`). Keep to that.
- Do not commit `.idea/`, `vendor/`, `tests/` scratch files, `.env` files or
  credentials.
- The PR description says **what changed, why, and how it was tested**, and
  flags any public API or behavior change.

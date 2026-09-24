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

`supa` is a Go SDK for [Supabase](https://supabase.com) with feature parity
with the official `supabase-js` client.

- **v2 (active)**: module `github.com/lengzuo/supa/v2` in `v2/` (Go major
  subdirectory layout), `go 1.23`. All new work happens here.
- **v1 (legacy)**: module `github.com/lengzuo/supa` at the repo root
  (`auth.go`, `postgres*.go`, `storage.go`, ...). Frozen: security fixes
  only. Do not add features to v1.

### v2 package map

| Package | Responsibility |
|---|---|
| `v2` (`supabase`) | `New(url, key, *Options)` composes every service; token plumbing (session or third-party `AccessToken`), auth→realtime token sync, global headers/HTTP client/request editors, `PropagateTrace`. |
| `v2/internal/transport` | The only HTTP code path. Header composition (canonical keys, per-request clone), apikey/Bearer rules, JSON encoding, retries, timeouts, redacted logging, `PathEscape`, `PreSendError`. |
| `v2/auth` | GoTrue: sign-in/up, sessions & refresh engine, auto-refresh, PKCE, `GetClaims`/JWKS, identities, passkeys, web3, MFA + recovery codes, admin API, OAuth server, ordered event delivery. |
| `v2/postgrest` | Immutable query builders, filters/modifiers, `Execute`/`ExecuteInto`/`ExecuteTo[T]`, RPC, schema, retry. |
| `v2/storage` | File buckets & objects, signed/public URLs, analytics (Iceberg REST catalog), vector buckets. |
| `v2/functions` | Edge Functions `Invoke` (streaming, regions, timeouts). |
| `v2/realtime` | Phoenix websocket client (JSON + binary serializers), channels, broadcast, presence, postgres changes. |
| `v2/compliance` | Maps every feature of the upstream capability matrix to Go symbols and tests; `TestCompliance` enforces it. |

### Upstream references

Behaviour must match the official clients in
[`supabase/supabase-js`](https://github.com/supabase/supabase-js)
(`packages/core/{auth-js,postgrest-js,storage-js,functions-js,realtime-js,supabase-js}`).
Read the upstream implementation and its tests before changing an endpoint.
Deliberate divergences are documented on the Go symbol and in the
compliance YAML.

## Conventions (v2)

- **Constructors**: each service has `New(Config) (*Client, error)`. The root
  `supabase.New` fills `URL`, `APIKey` and `AccessToken`; new settings are new
  `Config` fields (zero value = upstream default), never positional params.
- **All HTTP goes through `internal/transport`.** Never build `http.Request`s
  in a service package. User-supplied path segments go through
  `transport.PathEscape` (it also neutralises `.`/`..`). `transport.URL`
  rejects anything `net/url` would silently re-escape.
- **Tokens**: user-scoped calls take an explicit token argument; `""` means
  "use the stored session". Explicit-token calls never read or write the
  stored session and never emit events.
- **Errors**: each package has its own error type (`*auth.Error`,
  `*postgrest.Error`, `*storage.Error`, `functions.HTTPError/RelayError/
  FetchError`, realtime errors); callers use `errors.As`/`errors.Is`.
  Failures before a request is sent are `*transport.PreSendError` and are
  never retried.
- **Context** first, `error` last, every network call honours ctx.
- **Logging** via `*slog.Logger` only, off by default, never headers, bodies,
  tokens, keys or codes.
- **Doc comments** on every exported identifier, starting with its name.

## Hard-won rules (each was a real defect found in review)

1. **Never fall back to the API key when a session exists but cannot be
   loaded or refreshed.** With a secret key that silently bypasses RLS. Fail
   closed.
2. **Never write back a session snapshot taken before a network call.**
   Re-read under `sessionMu` and only commit if the stored session is still
   the one the request started from (see `updateStoredUser`,
   `replaceSessionIfCurrent`, `removalEpoch`).
3. **Never send a refresh token that storage has already rotated past.**
   GoTrue revokes the whole session on reuse.
4. **Auth events are queued under `sessionMu` in commit order** and delivered
   before the caller returns; never notify while holding a lock.
5. **Never hold a mutex across network I/O**; use single-flight with
   context-aware waiting.
6. **Headers are canonicalised and cloned per request.** A shared
   `http.Header` leaked tokens between users in v1.
7. **Redact secrets inside wrapped errors too** (`*url.Error.URL`), not just
   the outer message.
8. **Validate server-supplied path fragments** (e.g. the Iceberg prefix) with
   a strict whitelist; a hostile server must not be able to redirect a
   credentialed request to another service.
9. **Builders are immutable values**; zero values and nil receivers return
   errors, never panic.

## Commands

```sh
cd v2
gofmt -l .                        # must print nothing
go vet ./...
go test -race ./...               # includes the compliance gate
go test -race -count=10 -cpu 1,4 ./auth/ ./realtime/   # concurrency-heavy packages
golangci-lint run ./...           # must report 0 issues
```

## Testing standards

- Standard `testing` package only; `net/http/httptest` fakes, never a real
  Supabase project. Assert the wire format: method, path (raw `RequestURI`
  for escaping), query, headers, JSON body.
- Cite the upstream source above each endpoint test
  (`// upstream: auth-js src/GoTrueClient.ts signUp`).
- Concurrency-sensitive code needs `-race` tests that reproduce the
  interleaving deterministically (gates/barriers), not sleeps.
- Every README snippet has a compiled `Example` function
  (`v2/example_test.go`, `v2/*/example_test.go`).
- **Compliance**: when adding or changing a feature, update the mapping in
  `v2/compliance/*.yaml` (feature id → symbols → tests). When upstream adds
  features, regenerate `upstream_features.txt` from supabase-js
  `sdk-compliance.yaml`; `TestCompliance` fails until they are mapped.

## API design checklist

- [ ] Smallest exported surface that solves the problem?
- [ ] `context.Context` first, `error` last, errors inspectable with
      `errors.As`/`errors.Is`?
- [ ] New config as a `Config` field with a safe zero value?
- [ ] Safe for concurrent use, or documented otherwise?
- [ ] Anything that could log, return or persist a secret?
- [ ] Safe for multi-user servers (no hidden shared session/token state)?
- [ ] Doc comment, README example (compiled), tests, compliance mapping?
- [ ] Breaking change? v2 is unreleased; after release, breaking changes
      need a new major version.

## Git and PR hygiene

- Commit style: short imperative summaries with a prefix (`add:`, `fix:`,
  `docs:`, `chore:`, `refactor:`).
- Do not commit `.idea/`, `vendor/`, `tests/` scratch files, `.claude/`
  worktrees, `zz_*probe*_test.go` files, `.env` files or credentials.
- PR descriptions say what changed, why, how it was tested, and flag any
  public API or behaviour change.

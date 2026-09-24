package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/lengzuo/supa/v2/internal/transport"
)

// Error is returned for every failed Auth API call. Use errors.As to
// inspect it.
type Error struct {
	// Message is the human-readable message from the server.
	Message string
	// StatusCode is the HTTP status, or 0 for errors raised before a
	// response was received.
	StatusCode int
	// Code is the machine-readable GoTrue error code (see ErrorCode*
	// constants), when the server supplied one.
	Code string
	// WeakPasswordReasons is set when Code is ErrorCodeWeakPassword.
	WeakPasswordReasons []string
	// Retryable reports whether the server answered with an
	// infrastructure error (5xx, Cloudflare 52x) that may succeed if
	// retried. It only describes HTTP responses: network failures and
	// context errors are returned as-is (not as *Error) and are equally
	// transient.
	Retryable bool
	// RedirectError is the "error" parameter (e.g. "access_denied") of a
	// redirect URL rejected by GetSessionFromURL; Code then holds its
	// error_code and Message its error_description.
	RedirectError string

	// kind is an additional sentinel code this error matches under
	// errors.Is (e.g. an error_code from a redirect URL that is also an
	// ErrImplicitGrantRedirect).
	kind string
}

func (e *Error) Error() string {
	switch {
	case e.Code != "" && e.StatusCode != 0:
		return fmt.Sprintf("auth: %s (status %d, code %s)", e.Message, e.StatusCode, e.Code)
	case e.StatusCode != 0:
		return fmt.Sprintf("auth: %s (status %d)", e.Message, e.StatusCode)
	default:
		return "auth: " + e.Message
	}
}

// Is lets errors.Is match an *Error against the sentinel errors below (or
// any *Error with a Code) by Code. A server session_not_found error also
// matches ErrSessionMissing, like auth-js AuthSessionMissingError.
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	if !ok || t.Code == "" {
		return false
	}
	if t.Code == ErrSessionMissing.Code && e.Code == ErrorCodeSessionNotFound {
		return true
	}
	return e.Code == t.Code || (e.kind != "" && e.kind == t.Code)
}

// Frequently checked error codes. The full list is at
// https://supabase.com/docs/guides/auth/debugging/error-codes.
const (
	ErrorCodeSessionNotFound       = "session_not_found"
	ErrorCodeSessionExpired        = "session_expired"
	ErrorCodeRefreshTokenNotFound  = "refresh_token_not_found"
	ErrorCodeRefreshTokenReused    = "refresh_token_already_used"
	ErrorCodeInvalidCredentials    = "invalid_credentials"
	ErrorCodeWeakPassword          = "weak_password"
	ErrorCodeUserNotFound          = "user_not_found"
	ErrorCodeUserAlreadyExists     = "user_already_exists"
	ErrorCodeEmailNotConfirmed     = "email_not_confirmed"
	ErrorCodeOTPExpired            = "otp_expired"
	ErrorCodeMFAVerificationFailed = "mfa_verification_failed"
	ErrorCodeOverRequestRateLimit  = "over_request_rate_limit"
	ErrorCodeBadJWT                = "bad_jwt"
	ErrorCodeNoAuthorization       = "no_authorization"
	ErrorCodeIdentityNotFound      = "identity_not_found"
)

// Sentinel errors for client-side failures. Match with errors.Is (which
// compares codes, so returned errors may carry a more specific message).
// The sentinels are shared values: never modify their fields.
var (
	// ErrSessionMissing is returned when an operation needs a stored
	// session and none is present.
	ErrSessionMissing = &Error{Message: "auth session missing", Code: "session_missing"}
	// ErrInvalidJWT is returned when a token cannot be decoded or verified.
	ErrInvalidJWT = &Error{Message: "invalid JWT", Code: "invalid_jwt"}
	// ErrPKCEVerifierMissing is returned by ExchangeCodeForSession when no
	// code verifier was found in storage.
	ErrPKCEVerifierMissing = &Error{Message: "PKCE code verifier not found in storage", Code: "pkce_verifier_missing"}
	// ErrInvalidArgument is wrapped when a request is rejected client-side.
	ErrInvalidArgument = errors.New("auth: invalid argument")
	// ErrInvalidTokenResponse is returned when a sign-in endpoint answered
	// 2xx without a session or user.
	ErrInvalidTokenResponse = &Error{Message: "auth session or user missing from token response", Code: "invalid_token_response"}
	// ErrRefreshDiscarded is returned when a token refresh succeeded but its
	// result was discarded because the stored session changed while the
	// refresh was in flight (a concurrent sign-out or another refresh). The
	// stored session, if any, is left as the concurrent writer set it.
	ErrRefreshDiscarded = &Error{Message: "refresh discarded: the stored session changed while it was in flight", Code: "refresh_discarded"}
	// ErrImplicitGrantRedirect is matched (via errors.Is) by errors from
	// GetSessionFromURL for URLs that carry no usable implicit-grant
	// session or that do not match the configured FlowType.
	ErrImplicitGrantRedirect = &Error{Message: "implicit grant redirect error", Code: "implicit_grant_redirect"}
	// ErrPKCEGrantCodeExchange is matched (via errors.Is) by errors from
	// GetSessionFromURL for PKCE callback URLs that cannot be exchanged.
	ErrPKCEGrantCodeExchange = &Error{Message: "PKCE grant code exchange error", Code: "pkce_grant_code_exchange"}
)

// newError returns a client-side *Error carrying code so that it matches
// the sentinel with the same code under errors.Is.
func newError(code, msg string) *Error { return &Error{Message: msg, Code: code} }

// invalidJWT returns an error matching ErrInvalidJWT with a specific message.
func invalidJWT(msg string) *Error { return newError(ErrInvalidJWT.Code, msg) }

// isRetryable reports whether err is an infrastructure failure (5xx,
// network, timeout) that may succeed if retried. Failures that happened
// before the request was sent (a failing RequestEditor or token source)
// are not retryable: retrying cannot fix them.
func isRetryable(err error) bool {
	if err == nil || transport.IsPreSend(err) {
		return false
	}
	var e *Error
	if errors.As(err, &e) {
		return e.Retryable
	}
	return true
}

// isSessionMissing reports whether err means the user has no (valid)
// session: the client-side ErrSessionMissing or the server's
// session_not_found code.
func isSessionMissing(err error) bool {
	var e *Error
	if !errors.As(err, &e) {
		return false
	}
	return e.Code == ErrSessionMissing.Code || e.Code == ErrorCodeSessionNotFound
}

// networkErrorCodes mirror auth-js: infrastructure failures that must not
// invalidate a session.
var networkErrorCodes = map[int]bool{
	500: true, 501: true, 502: true, 503: true, 504: true,
	520: true, 521: true, 522: true, 523: true, 524: true, 525: true,
	526: true, 527: true, 528: true, 529: true, 530: true,
}

// apiVersion20240101 is the first GoTrue API version that returns error
// codes in the "code" field.
var apiVersion20240101 = time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

// maxErrorBodyMessage bounds how much of a non-JSON error body becomes
// the error message.
const maxErrorBodyMessage = 512

// toError converts transport errors into *Error, mirroring auth-js
// handleError. Non-HTTP errors (context cancellation, network failures,
// pre-send failures) are returned unchanged so errors.Is still works on
// them; isRetryable treats them as retryable except pre-send failures.
func toError(err error) error {
	if err == nil {
		return nil
	}
	var he *transport.HTTPError
	if !errors.As(err, &he) {
		return err
	}
	out := &Error{StatusCode: he.StatusCode, Retryable: networkErrorCodes[he.StatusCode]}

	// Decode field by field so one badly typed field does not lose the
	// others.
	var fields map[string]json.RawMessage
	if jerr := json.Unmarshal(he.Body, &fields); jerr != nil {
		var anyJSON any
		switch {
		case json.Unmarshal(he.Body, &anyJSON) == nil:
			// Valid JSON that is not an object (auth-js: JSON.stringify).
			out.Message = truncateMessage(string(he.Body))
		case out.Retryable || len(he.Body) == 0:
			out.Message = httpStatusMessage(he.StatusCode)
		default:
			out.Message = truncateMessage(string(he.Body))
		}
		return out
	}
	str := func(key string) string {
		var v string
		if raw, ok := fields[key]; ok && json.Unmarshal(raw, &v) == nil {
			return v
		}
		return ""
	}
	for _, key := range []string{"msg", "message", "error_description", "error"} {
		if v := str(key); v != "" {
			out.Message = v
			break
		}
	}
	if out.Message == "" {
		out.Message = truncateMessage(string(he.Body))
	}
	if out.Retryable {
		// Infrastructure failure: like auth-js AuthRetryableFetchError, no
		// error code is extracted.
		return out
	}
	code := ""
	if v := he.Header.Get(APIVersionHeader); v != "" {
		if t, err := time.Parse("2006-01-02", v); err == nil && !t.Before(apiVersion20240101) {
			code = str("code")
		}
	}
	if code == "" {
		code = str("error_code")
	}
	out.Code = code
	var weak struct {
		Reasons []string `json:"reasons"`
	}
	hasWeak := false
	if raw, ok := fields["weak_password"]; ok && json.Unmarshal(raw, &weak) == nil && weak.Reasons != nil {
		hasWeak = true
	}
	switch {
	case code == ErrorCodeWeakPassword:
		out.WeakPasswordReasons = weak.Reasons
		if out.WeakPasswordReasons == nil {
			out.WeakPasswordReasons = []string{}
		}
	case code == "" && hasWeak && len(weak.Reasons) > 0:
		out.Code = ErrorCodeWeakPassword
		out.WeakPasswordReasons = weak.Reasons
	}
	return out
}

// httpStatusMessage is the status text, or "HTTP <status>" for codes Go
// does not name (e.g. Cloudflare's 520-530).
func httpStatusMessage(status int) string {
	if t := http.StatusText(status); t != "" {
		return t
	}
	return fmt.Sprintf("HTTP %d", status)
}

func truncateMessage(s string) string {
	if len(s) > maxErrorBodyMessage {
		return s[:maxErrorBodyMessage]
	}
	return s
}

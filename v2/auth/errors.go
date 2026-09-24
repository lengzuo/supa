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
	// Retryable reports whether the failure was an infrastructure error
	// (5xx or network) that may succeed if retried.
	Retryable bool
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

// Is lets errors.Is match an *Error against the sentinel errors below by Code.
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	if !ok || t.Code == "" {
		return false
	}
	return e.Code == t.Code
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

// Sentinel errors for client-side failures. Match with errors.Is.
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
)

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

// toError converts transport errors into *Error. Non-HTTP errors (context
// cancellation, network failures) are returned wrapped so errors.Is still
// works on them.
func toError(err error) error {
	if err == nil {
		return nil
	}
	var he *transport.HTTPError
	if !errors.As(err, &he) {
		return err
	}
	var body struct {
		Code             json.RawMessage `json:"code"`
		ErrorCode        string          `json:"error_code"`
		Msg              string          `json:"msg"`
		Message          string          `json:"message"`
		ErrorDescription string          `json:"error_description"`
		Error            string          `json:"error"`
		WeakPassword     *struct {
			Reasons []string `json:"reasons"`
		} `json:"weak_password"`
	}
	out := &Error{StatusCode: he.StatusCode, Retryable: networkErrorCodes[he.StatusCode]}
	if jerr := json.Unmarshal(he.Body, &body); jerr != nil {
		out.Message = http.StatusText(he.StatusCode)
		if len(he.Body) > 0 && !out.Retryable {
			out.Message = string(he.Body)
		}
		return out
	}
	switch {
	case body.Msg != "":
		out.Message = body.Msg
	case body.Message != "":
		out.Message = body.Message
	case body.ErrorDescription != "":
		out.Message = body.ErrorDescription
	case body.Error != "":
		out.Message = body.Error
	default:
		out.Message = string(he.Body)
	}
	var code string
	if v := he.Header.Get(APIVersionHeader); v != "" {
		if t, err := time.Parse("2006-01-02", v); err == nil && !t.Before(apiVersion20240101) {
			_ = json.Unmarshal(body.Code, &code)
		}
	}
	if code == "" {
		code = body.ErrorCode
	}
	out.Code = code
	if body.WeakPassword != nil && (code == ErrorCodeWeakPassword || (code == "" && len(body.WeakPassword.Reasons) > 0)) {
		out.Code = ErrorCodeWeakPassword
		out.WeakPasswordReasons = body.WeakPassword.Reasons
	}
	return out
}

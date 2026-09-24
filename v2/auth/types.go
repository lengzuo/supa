package auth

import (
	"encoding/json"
	"time"
)

// Session is an authenticated session returned by sign-in and refresh.
type Session struct {
	AccessToken          string `json:"access_token"`
	RefreshToken         string `json:"refresh_token"`
	TokenType            string `json:"token_type"`
	ExpiresIn            int64  `json:"expires_in"`
	ExpiresAt            int64  `json:"expires_at,omitempty"`
	ProviderToken        string `json:"provider_token,omitempty"`
	ProviderRefreshToken string `json:"provider_refresh_token,omitempty"`
	User                 *User  `json:"user,omitempty"`
}

// Expiry returns the session expiry time.
func (s *Session) Expiry() time.Time { return time.Unix(s.ExpiresAt, 0) }

// User is a Supabase Auth user.
type User struct {
	ID                 string          `json:"id"`
	Aud                string          `json:"aud"`
	Role               string          `json:"role,omitempty"`
	Email              string          `json:"email,omitempty"`
	Phone              string          `json:"phone,omitempty"`
	NewEmail           string          `json:"new_email,omitempty"`
	NewPhone           string          `json:"new_phone,omitempty"`
	ActionLink         string          `json:"action_link,omitempty"`
	AppMetadata        map[string]any  `json:"app_metadata"`
	UserMetadata       map[string]any  `json:"user_metadata"`
	Identities         []Identity      `json:"identities,omitempty"`
	Factors            []Factor        `json:"factors,omitempty"`
	IsAnonymous        bool            `json:"is_anonymous"`
	IsSSOUser          bool            `json:"is_sso_user,omitempty"`
	CreatedAt          time.Time       `json:"created_at"`
	UpdatedAt          *time.Time      `json:"updated_at,omitempty"`
	ConfirmedAt        *time.Time      `json:"confirmed_at,omitempty"`
	EmailConfirmedAt   *time.Time      `json:"email_confirmed_at,omitempty"`
	PhoneConfirmedAt   *time.Time      `json:"phone_confirmed_at,omitempty"`
	ConfirmationSentAt *time.Time      `json:"confirmation_sent_at,omitempty"`
	RecoverySentAt     *time.Time      `json:"recovery_sent_at,omitempty"`
	EmailChangeSentAt  *time.Time      `json:"email_change_sent_at,omitempty"`
	InvitedAt          *time.Time      `json:"invited_at,omitempty"`
	LastSignInAt       *time.Time      `json:"last_sign_in_at,omitempty"`
	BannedUntil        *time.Time      `json:"banned_until,omitempty"`
	DeletedAt          *time.Time      `json:"deleted_at,omitempty"`
	Raw                json.RawMessage `json:"-"`
}

// UnmarshalJSON keeps the raw payload in Raw so fields this SDK does not
// model are still available.
func (u *User) UnmarshalJSON(data []byte) error {
	type plain User
	var p plain
	if err := json.Unmarshal(data, &p); err != nil {
		return err
	}
	*u = User(p)
	u.Raw = append(json.RawMessage(nil), data...)
	return nil
}

// Identity links a user to a sign-in provider.
type Identity struct {
	ID           string         `json:"id"`
	IdentityID   string         `json:"identity_id"`
	UserID       string         `json:"user_id"`
	Provider     string         `json:"provider"`
	IdentityData map[string]any `json:"identity_data,omitempty"`
	CreatedAt    *time.Time     `json:"created_at,omitempty"`
	LastSignInAt *time.Time     `json:"last_sign_in_at,omitempty"`
	UpdatedAt    *time.Time     `json:"updated_at,omitempty"`
}

// FactorType is an MFA factor type.
type FactorType string

const (
	FactorTypeTOTP         FactorType = "totp"
	FactorTypePhone        FactorType = "phone"
	FactorTypeWebAuthn     FactorType = "webauthn"
	FactorTypeRecoveryCode FactorType = "recovery_code"
)

// FactorStatus is an MFA factor's verification status.
type FactorStatus string

const (
	FactorStatusVerified   FactorStatus = "verified"
	FactorStatusUnverified FactorStatus = "unverified"
)

// Factor is an MFA factor enrolled by a user.
type Factor struct {
	ID               string       `json:"id"`
	FriendlyName     string       `json:"friendly_name,omitempty"`
	FactorType       FactorType   `json:"factor_type"`
	Status           FactorStatus `json:"status"`
	Phone            string       `json:"phone,omitempty"`
	CreatedAt        time.Time    `json:"created_at"`
	UpdatedAt        time.Time    `json:"updated_at"`
	LastChallengedAt *time.Time   `json:"last_challenged_at,omitempty"`
}

// AMREntry is one authentication-method-reference claim in an access token.
type AMREntry struct {
	Method    string `json:"method"`
	Timestamp int64  `json:"timestamp"`
}

// AuthChangeEvent is delivered to OnAuthStateChange listeners.
type AuthChangeEvent string

const (
	EventInitialSession       AuthChangeEvent = "INITIAL_SESSION"
	EventPasswordRecovery     AuthChangeEvent = "PASSWORD_RECOVERY"
	EventSignedIn             AuthChangeEvent = "SIGNED_IN"
	EventSignedOut            AuthChangeEvent = "SIGNED_OUT"
	EventTokenRefreshed       AuthChangeEvent = "TOKEN_REFRESHED"
	EventUserUpdated          AuthChangeEvent = "USER_UPDATED"
	EventMFAChallengeVerified AuthChangeEvent = "MFA_CHALLENGE_VERIFIED"
)

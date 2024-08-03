package supabase

import "time"

type AuthDetailResp struct {
	AccessToken          string `json:"access_token,omitempty" url:"-"`
	RefreshToken         string `json:"refresh_token,omitempty" url:"-"`
	TokenType            string `json:"token_type,omitempty" url:"-"`
	ExpiresIn            uint   `json:"expires_in,omitempty" url:"-"`
	ExpiresAt            uint64 `json:"expires_at,omitempty" url:"-"`
	ProviderToken        string `json:"provider_token,omitempty" url:"-"`
	ProviderRefreshToken string `json:"provider_refresh_token,omitempty" url:"-"`
	User                 User   `json:"user" url:"-"`
}

type GotrueMeta struct {
	CaptchaToken string `json:"captcha_token,omitempty" url:"-"`
}

type Options struct {
	CaptchaToken string      `json:"captcha_token" url:"-"`
	Data         interface{} `json:"data,omitempty" url:"-"`
}

type SignInRequest struct {
	Email               string      `json:"email,omitempty" url:"-"`
	Phone               string      `json:"phone,omitempty" url:"-"`
	Channel             string      `json:"channel,omitempty" url:"-"`
	Password            string      `json:"password" url:"-"`
	CreateUser          bool        `json:"create_user,omitempty" url:"-"`
	Data                interface{} `json:"data,omitempty" url:"-"`
	CodeChallengeMethod string      `json:"code_challenge_method,omitempty" url:"-"`
	CodeChallenge       string      `json:"code_challenge,omitempty" url:"-"`
	GotrueMetaSecurity  GotrueMeta  `json:"gotrue_meta_security,omitempty" url:"-"`
	Options             Options     `json:"options,omitempty" url:"-"`
	RedirectTo          string      `json:"-" url:"redirect_to,omitempty"`
}

type VerifyRequest struct {
	Email     string `json:"email" url:"-"`
	Phone     string `json:"phone,omitempty" url:"-"`
	Token     string `json:"token,omitempty" url:"-"`
	TokenHash string `json:"token_hash,omitempty" url:"-"`
	Type      string `json:"type,omitempty" url:"-"`
}

type SignUpRequest struct {
	Email              string      `json:"email,omitempty" url:"-"`
	Password           string      `json:"password" url:"-"`
	GotrueMetaSecurity GotrueMeta  `json:"gotrue_meta_security,omitempty" url:"-"`
	Data               interface{} `json:"data,omitempty" url:"-"`
	Phone              string      `json:"phone,omitempty" url:"-"`
	Channel            string      `json:"channel,omitempty" url:"-"`
	EmailRedirectTo    string      `json:"-" url:"redirect_to,omitempty"`
}

type RefreshTokenReq struct {
	RefreshToken string `json:"refresh_token,omitempty" url:"-"`
}

type OAuthSignInRequest struct {
	RedirectTo       string `json:"-" url:"redirect_to,omitempty"`
	Scopes           string `json:"-" url:"scopes,omitempty"`
	Provider         string `json:"-" url:"provider,omitempty"`
	SkipHTTPRedirect string `json:"-" url:"skip_http_redirect,omitempty"`
}

type SignInWithIDTokenRequest struct {
	AccessToken        string     `json:"access_token" url:"-"`
	GotrueMetaSecurity GotrueMeta `json:"gotrue_meta_security,omitempty" url:"-"`
	IDToken            string     `json:"id_token" url:"-"`
	Nonce              string     `json:"nonce" url:"-"`
	Provider           string     `json:"provider,omitempty" url:"-"`
}

type ResetPasswordForEmailRequest struct {
	Email               string     `json:"email" url:"-"`
	CodeChallengeMethod string     `json:"code_challenge_method,omitempty" url:"-"`
	CodeChallenge       string     `json:"code_challenge,omitempty" url:"-"`
	GotrueMetaSecurity  GotrueMeta `json:"gotrue_meta_security,omitempty" url:"-"`
	RedirectTo          string     `json:"-" url:"redirect_to,omitempty"`
}

type UpdateUserRequest struct {
	Email      string      `json:"email,omitempty" url:"-"`
	Phone      string      `json:"phone,omitempty" url:"-"`
	Password   string      `json:"password,omitempty" url:"-"`
	Nonce      string      `json:"nonce,omitempty" url:"-"`
	Data       interface{} `json:"data,omitempty" url:"-"`
	RedirectTo string      `json:"-" url:"redirect_to,omitempty"`
}

type SignInAnonymousRequest struct {
	Data               interface{} `json:"data,omitempty" url:"-"`
	GotrueMetaSecurity GotrueMeta  `json:"gotrue_meta_security,omitempty" url:"-"`
}

type TransformOptions struct {
	Width   int    `json:"width"`
	Height  int    `json:"height"`
	Resize  string `json:"resize"`
	Format  string `json:"format"`
	Quality int    `json:"quality"`
}

type UrlOptions struct {
	Transform *TransformOptions `json:"transform"`
	Download  bool              `json:"download"`
}

type AppMetadata struct {
	Provider string `json:"provider"`
}

type UserMeta struct {
	Name string `json:"name"`
}

type User struct {
	ID                 string      `json:"id"`
	Aud                string      `json:"aud"`
	Role               string      `json:"role"`
	Email              string      `json:"email"`
	InvitedAt          time.Time   `json:"invited_at"`
	ConfirmedAt        time.Time   `json:"confirmed_at"`
	ConfirmationSentAt time.Time   `json:"confirmation_sent_at"`
	AppMetadata        AppMetadata `json:"app_metadata"`
	Metadata           UserMeta    `json:"user_metadata"`
	CreatedAt          time.Time   `json:"created_at"`
	UpdatedAt          time.Time   `json:"updated_at"`
}

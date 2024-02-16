package dto

type AuthDetailResp struct {
	AccessToken          string `json:"access_token,omitempty"`
	RefreshToken         string `json:"refresh_token,omitempty"`
	TokenType            string `json:"token_type,omitempty"`
	ExpiresIn            uint   `json:"expires_in,omitempty"`
	ExpiresAt            uint64 `json:"expires_at,omitempty"`
	ProviderToken        string `json:"provider_token,omitempty"`
	ProviderRefreshToken string `json:"provider_refresh_token,omitempty"`
	User                 User   `json:"user"`
}

type GotrueMeta struct {
	CaptchaToken string `json:"captcha_token,omitempty"`
}

type Options struct {
	CaptchaToken string      `json:"captcha_token"`
	Data         interface{} `json:"data"`
}

type SignInRequest struct {
	Email               string     `json:"email,omitempty"`
	Phone               string     `json:"phone,omitempty"`
	Channel             string     `json:"channel,omitempty"`
	Password            string     `json:"password"`
	CreateUser          bool       `json:"create_user,omitempty"`
	Data                string     `json:"data,omitempty"`
	CodeChallengeMethod string     `json:"code_challenge_method,omitempty"`
	CodeChallenge       string     `json:"code_challenge,omitempty"`
	GotrueMetaSecurity  GotrueMeta `json:"gotrue_meta_security,omitempty"`
	Options             Options    `json:"options,omitempty"`
}

type VerifyRequest struct {
	Email     string `json:"email"`
	Phone     string `json:"phone,omitempty"`
	Token     string `json:"token,omitempty"`
	TokenHash string `json:"token_hash,omitempty"`
	Type      string `json:"type,omitempty"`
}

type SignUpRequest struct {
	Email              string      `json:"email,omitempty"`
	Password           string      `json:"password"`
	GotrueMetaSecurity GotrueMeta  `json:"gotrue_meta_security,omitempty"`
	EmailRedirectTo    string      `query:"redirect_to,omitempty"`
	Data               interface{} `json:"data,omitempty"`
	Phone              string      `json:"phone,omitempty"`
	Channel            string      `json:"channel,omitempty"`
}

type RefreshTokenReq struct {
	RefreshToken string `json:"refresh_token,omitempty"`
}

type OAuthSignInRequest struct {
	RedirectTo       string `url:"redirect_to,omitempty"`
	Scopes           string `url:"scopes,omitempty"`
	Provider         string `url:"provider,omitempty"`
	SkipHTTPRedirect string `url:"skip_http_redirect,omitempty"`
}

type SignInWithIDTokenRequest struct {
	AccessToken        string     `json:"access_token"`
	GotrueMetaSecurity GotrueMeta `json:"gotrue_meta_security,omitempty"`
	IDToken            string     `json:"id_token"`
	Nonce              string     `json:"nonce"`
	Provider           string     `json:"provider,omitempty"`
}

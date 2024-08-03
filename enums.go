package supabase

type Header uint8

const (
	HeaderAuthorization Header = iota
	HeaderContentType
	HeaderAccept
)

func (v Header) String() string {
	return [...]string{"Authorization", "Content-Type", "Accept"}[v]
}

type VerifyType uint8

const (
	VerifyTypeSignUp VerifyType = iota
	VerifyTypeInvite
	VerifyTypeMagicLink
	VerifyTypeRecovery
	VerifyTypeEmailChange
	VerifyTypeEmail
	VerifyTypeSms
	VerifyTypePhoneChange
)

func (v VerifyType) String() string {
	return [...]string{"signup", "invite", "magiclink", "recovery", "email_change", "email", "sms", "phone_change"}[v]
}

type Order uint8

const (
	OrderAsc Order = iota
	OrderDesc
)

func (v Order) String() string {
	return [...]string{"asc", "desc"}[v]
}

type Provider uint8

const (
	ProviderApple Provider = iota
	ProviderAzure
	ProviderBitbucket
	ProviderDiscord
	ProviderFacebook
	ProviderFigma
	ProviderGithub
	ProviderGitlab
	ProviderGoogle
	ProviderKakao
	ProviderKeycloak
	ProviderLinkedin
	ProviderLinkedinOIDC
	ProviderNotion
	ProviderSlack
	ProviderSpotify
	ProviderTwitch
	ProviderTwitter
	ProviderWorkos
	ProviderZoom
	ProviderFly
)

func (v Provider) String() string {
	return [...]string{
		"apple",
		"azure",
		"bitbucket",
		"discord",
		"facebook",
		"figma",
		"github",
		"gitlab",
		"google",
		"kakao",
		"keycloak",
		"linkedin",
		"linkedin_oidc",
		"notion",
		"slack",
		"spotify",
		"twitch",
		"twitter",
		"workos",
		"zoom",
		"fly",
	}[v]
}

package enum

type Provider uint8

const (
	Apple Provider = iota
	Azure
	Bitbucket
	Discord
	Facebook
	Figma
	Github
	Gitlab
	Google
	Kakao
	Keycloak
	Linkedin
	LinkedinOIDC
	Notion
	Slack
	Spotify
	Twitch
	Twitter
	Workos
	Zoom
	Fly
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

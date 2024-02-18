package enum

type VerifyType uint8

const (
	SignUp VerifyType = iota
	Invite
	MagicLink
	Recovery
	EmailChange
	Email
	Sms
	PhoneChange
)

func (v VerifyType) String() string {
	return [...]string{"signup", "invite", "magiclink", "recovery", "email_change", "email", "sms", "phone_change"}[v]
}

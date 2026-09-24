package auth

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Web3Chain is a blockchain supported by SignInWithWeb3.
type Web3Chain string

const (
	// Web3ChainEthereum signs in with a Sign-In with Ethereum (EIP-4361)
	// message signed via personal_sign.
	Web3ChainEthereum Web3Chain = "ethereum"
	// Web3ChainSolana signs in with a Sign-In with Solana message.
	Web3ChainSolana Web3Chain = "solana"
)

// SignInWithWeb3Params carry a message already signed by the user's wallet
// (wallet interaction happens client-side; see CreateSIWEMessage and
// CreateSolanaSignInMessage to build the message on the server).
type SignInWithWeb3Params struct {
	Chain Web3Chain
	// Message is the exact text that was signed.
	Message string
	// Signature is the raw signature bytes: for Ethereum the 65-byte
	// personal_sign signature (hex-decode the wallet's 0x string), for
	// Solana the 64-byte ed25519 signature.
	Signature    []byte
	CaptchaToken string
}

// SignInWithWeb3 signs in with a signed wallet message
// (POST /token?grant_type=web3), stores the session and emits SIGNED_IN.
// Web3 sign-in must be enabled for the project.
func (c *Client) SignInWithWeb3(ctx context.Context, params SignInWithWeb3Params) (*AuthResponse, error) {
	if params.Message == "" || len(params.Signature) == 0 {
		return nil, fmt.Errorf("%w: message and signature are required", ErrInvalidArgument)
	}
	var signature string
	switch params.Chain {
	case Web3ChainEthereum:
		signature = "0x" + hex.EncodeToString(params.Signature)
	case Web3ChainSolana:
		signature = base64.RawURLEncoding.EncodeToString(params.Signature)
	default:
		return nil, fmt.Errorf("%w: unsupported chain %q", ErrInvalidArgument, params.Chain)
	}
	body := struct {
		Chain     Web3Chain           `json:"chain"`
		Message   string              `json:"message"`
		Signature string              `json:"signature"`
		Meta      *gotrueMetaSecurity `json:"gotrue_meta_security,omitempty"`
	}{params.Chain, params.Message, signature, optionalMeta(params.CaptchaToken)}
	return c.signInToken(ctx, "web3", "", body, EventSignedIn)
}

// SIWEMessage describes a Sign-In with Ethereum (EIP-4361) message.
type SIWEMessage struct {
	// Scheme is the optional URI scheme of the origin (e.g. "https").
	Scheme string
	// Domain is the RFC 3986 authority requesting the sign-in (host[:port]).
	Domain string
	// Address is the 0x-prefixed Ethereum address performing the signing.
	Address string
	// Statement is an optional human-readable assertion (no newlines).
	Statement string
	// URI is the resource that is the subject of the signing.
	URI string
	// ChainID is the EIP-155 chain id.
	ChainID int
	// Nonce is an optional random string (at least 8 characters).
	Nonce string
	// IssuedAt defaults to the current time.
	IssuedAt       time.Time
	ExpirationTime time.Time
	NotBefore      time.Time
	RequestID      string
	Resources      []string
}

var ethAddressPattern = regexp.MustCompile(`^0x[a-fA-F0-9]{40}$`)

// jsISOString formats t like JavaScript's Date.prototype.toISOString.
func jsISOString(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000Z") }

// CreateSIWEMessage renders m in the EIP-4361 format auth-js produces, for
// the user's wallet to sign with personal_sign.
func CreateSIWEMessage(m SIWEMessage) (string, error) {
	switch {
	case m.ChainID <= 0:
		return "", fmt.Errorf("%w: SIWE chain id must be an EIP-155 chain id", ErrInvalidArgument)
	case m.Domain == "":
		return "", fmt.Errorf("%w: SIWE domain must be provided", ErrInvalidArgument)
	case m.Nonce != "" && len(m.Nonce) < 8:
		return "", fmt.Errorf("%w: SIWE nonce must be at least 8 characters", ErrInvalidArgument)
	case m.URI == "":
		return "", fmt.Errorf("%w: SIWE uri must be provided", ErrInvalidArgument)
	case strings.Contains(m.Statement, "\n"):
		return "", fmt.Errorf("%w: SIWE statement must not include newlines", ErrInvalidArgument)
	case !ethAddressPattern.MatchString(m.Address):
		return "", fmt.Errorf("%w: invalid Ethereum address", ErrInvalidArgument)
	}
	issuedAt := m.IssuedAt
	if issuedAt.IsZero() {
		issuedAt = time.Now()
	}
	origin := m.Domain
	if m.Scheme != "" {
		origin = m.Scheme + "://" + m.Domain
	}
	var b strings.Builder
	b.WriteString(origin + " wants you to sign in with your Ethereum account:\n")
	b.WriteString(strings.ToLower(m.Address) + "\n\n")
	if m.Statement != "" {
		b.WriteString(m.Statement + "\n")
	}
	b.WriteString("\nURI: " + m.URI)
	b.WriteString("\nVersion: 1")
	b.WriteString("\nChain ID: " + strconv.Itoa(m.ChainID))
	if m.Nonce != "" {
		b.WriteString("\nNonce: " + m.Nonce)
	}
	b.WriteString("\nIssued At: " + jsISOString(issuedAt))
	if !m.ExpirationTime.IsZero() {
		b.WriteString("\nExpiration Time: " + jsISOString(m.ExpirationTime))
	}
	if !m.NotBefore.IsZero() {
		b.WriteString("\nNot Before: " + jsISOString(m.NotBefore))
	}
	if m.RequestID != "" {
		b.WriteString("\nRequest ID: " + m.RequestID)
	}
	if m.Resources != nil {
		b.WriteString("\nResources:")
		for _, r := range m.Resources {
			if r == "" {
				return "", fmt.Errorf("%w: SIWE resources must be non-empty strings", ErrInvalidArgument)
			}
			b.WriteString("\n- " + r)
		}
	}
	return b.String(), nil
}

// SolanaSignInMessage describes a Sign-In with Solana message.
type SolanaSignInMessage struct {
	// URI is the page the sign-in happens on; Domain defaults to its host.
	URI    string
	Domain string
	// Address is the base58 public key of the signing account.
	Address   string
	Statement string
	// IssuedAt defaults to the current time.
	IssuedAt       time.Time
	NotBefore      time.Time
	ExpirationTime time.Time
	ChainID        string
	Nonce          string
	RequestID      string
	Resources      []string
}

// CreateSolanaSignInMessage renders m in the format auth-js produces for
// wallets without a native signIn method.
func CreateSolanaSignInMessage(m SolanaSignInMessage) (string, error) {
	if m.URI == "" || m.Address == "" {
		return "", fmt.Errorf("%w: uri and address are required", ErrInvalidArgument)
	}
	domain := m.Domain
	if domain == "" {
		u, err := url.Parse(m.URI)
		if err != nil || u.Host == "" {
			return "", fmt.Errorf("%w: uri must be an absolute URL", ErrInvalidArgument)
		}
		domain = u.Host
	}
	issuedAt := m.IssuedAt
	if issuedAt.IsZero() {
		issuedAt = time.Now()
	}
	lines := []string{domain + " wants you to sign in with your Solana account:", m.Address}
	if m.Statement != "" {
		lines = append(lines, "", m.Statement, "")
	} else {
		lines = append(lines, "")
	}
	lines = append(lines, "Version: 1", "URI: "+m.URI, "Issued At: "+jsISOString(issuedAt))
	if !m.NotBefore.IsZero() {
		lines = append(lines, "Not Before: "+jsISOString(m.NotBefore))
	}
	if !m.ExpirationTime.IsZero() {
		lines = append(lines, "Expiration Time: "+jsISOString(m.ExpirationTime))
	}
	if m.ChainID != "" {
		lines = append(lines, "Chain ID: "+m.ChainID)
	}
	if m.Nonce != "" {
		lines = append(lines, "Nonce: "+m.Nonce)
	}
	if m.RequestID != "" {
		lines = append(lines, "Request ID: "+m.RequestID)
	}
	if len(m.Resources) > 0 {
		lines = append(lines, "Resources")
		for _, r := range m.Resources {
			lines = append(lines, "- "+r)
		}
	}
	return strings.Join(lines, "\n"), nil
}

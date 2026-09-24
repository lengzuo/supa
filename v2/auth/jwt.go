package auth

import (
	"encoding/base64"
	"encoding/json"
	"strings"
)

// JWTHeader is the decoded header of a JWT.
type JWTHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid,omitempty"`
	Typ string `json:"typ,omitempty"`
}

// Claims are the claims carried by a Supabase access token.
type Claims struct {
	Issuer       string         `json:"iss,omitempty"`
	Subject      string         `json:"sub,omitempty"`
	Audience     any            `json:"aud,omitempty"`
	ExpiresAt    int64          `json:"exp,omitempty"`
	IssuedAt     int64          `json:"iat,omitempty"`
	Role         string         `json:"role,omitempty"`
	AAL          string         `json:"aal,omitempty"`
	SessionID    string         `json:"session_id,omitempty"`
	Email        string         `json:"email,omitempty"`
	Phone        string         `json:"phone,omitempty"`
	IsAnonymous  bool           `json:"is_anonymous,omitempty"`
	AMR          []AMREntry     `json:"amr,omitempty"`
	AppMetadata  map[string]any `json:"app_metadata,omitempty"`
	UserMetadata map[string]any `json:"user_metadata,omitempty"`
	// Raw holds every claim, including ones not modeled above.
	Raw map[string]any `json:"-"`
}

// decodedJWT is a parsed but unverified JWT.
type decodedJWT struct {
	Header       JWTHeader
	Claims       Claims
	SigningInput string // base64url(header) + "." + base64url(payload)
	Signature    []byte
}

// decodeJWT parses token without verifying its signature.
func decodeJWT(token string) (*decodedJWT, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, ErrInvalidJWT
	}
	dec := base64.RawURLEncoding
	hdr, err := dec.DecodeString(parts[0])
	if err != nil {
		return nil, ErrInvalidJWT
	}
	payload, err := dec.DecodeString(parts[1])
	if err != nil {
		return nil, ErrInvalidJWT
	}
	sig, err := dec.DecodeString(parts[2])
	if err != nil {
		return nil, ErrInvalidJWT
	}
	out := &decodedJWT{SigningInput: parts[0] + "." + parts[1], Signature: sig}
	if err := json.Unmarshal(hdr, &out.Header); err != nil {
		return nil, ErrInvalidJWT
	}
	if err := json.Unmarshal(payload, &out.Claims); err != nil {
		return nil, ErrInvalidJWT
	}
	if err := json.Unmarshal(payload, &out.Claims.Raw); err != nil {
		return nil, ErrInvalidJWT
	}
	return out, nil
}

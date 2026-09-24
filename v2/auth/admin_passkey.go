package auth

import (
	"context"
	"net/http"
	"time"

	"github.com/lengzuo/supa/v2/internal/transport"
)

// AdminPasskeyAPI manages users' passkeys. Obtain it with AdminAPI.Passkey.
type AdminPasskeyAPI struct {
	c *Client
}

// AdminPasskey is a passkey registered by a user, as listed by the admin
// API.
type AdminPasskey struct {
	ID           string     `json:"id"`
	FriendlyName string     `json:"friendly_name,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	LastUsedAt   *time.Time `json:"last_used_at,omitempty"`
}

// List returns the passkeys of the user, whose ID must be a UUID.
func (p *AdminPasskeyAPI) List(ctx context.Context, userID string) ([]AdminPasskey, error) {
	if err := adminValidateUUID("user ID", userID); err != nil {
		return nil, err
	}
	var out []AdminPasskey
	if _, err := p.c.adminRequest(ctx, &transport.Request{Method: http.MethodGet, Path: "/admin/users/" + pathSegment(userID) + "/passkeys"}, &out); err != nil {
		return nil, err
	}
	if out == nil {
		out = []AdminPasskey{}
	}
	return out, nil
}

// Delete deletes the passkey passkeyID of the user userID (both
// UUIDs).
func (p *AdminPasskeyAPI) Delete(ctx context.Context, userID, passkeyID string) error {
	if err := adminValidateUUID("user ID", userID); err != nil {
		return err
	}
	if err := adminValidateUUID("passkey ID", passkeyID); err != nil {
		return err
	}
	_, err := p.c.adminRequest(ctx, &transport.Request{Method: http.MethodDelete, Path: "/admin/users/" + pathSegment(userID) + "/passkeys/" + pathSegment(passkeyID)}, nil)
	return err
}

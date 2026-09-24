package auth

import "context"

// GetSession returns the stored session, or (nil, nil) when there is none.
//
// FOUNDATION STUB: the auth-core work item owns this file and must extend
// GetSession to refresh a session that is expired or about to expire,
// keeping this signature.
func (c *Client) GetSession(ctx context.Context) (*Session, error) {
	return c.loadSession(ctx)
}

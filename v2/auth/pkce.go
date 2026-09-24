package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// PKCEFlowIDParam is the reserved query parameter that carries a PKCE flow
// id through a redirect (see Config.AppendPKCEFlowIDToRedirects).
const PKCEFlowIDParam = "sb_flow_id"

// pkceMaxConcurrentFlows bounds the number of pending verifier slots;
// starting another flow evicts the oldest one (auth-js
// PKCE_MAX_CONCURRENT_FLOWS).
const pkceMaxConcurrentFlows = 5

var pkceFlowIDPattern = regexp.MustCompile(`^[a-zA-Z0-9_-]{8,64}$`)

// validPKCEFlowID returns id if it is a plausible flow id, "" otherwise.
// Flow ids arrive via URLs, so anything else is discarded before it is used
// to build a storage key.
func validPKCEFlowID(id string) string {
	if pkceFlowIDPattern.MatchString(id) {
		return id
	}
	return ""
}

// Storage keys match auth-js so a storage shared with a JS client (for
// example cookies in an SSR setup) interoperates.
func (c *Client) pkceLegacyKey() string { return c.storageKey + "-code-verifier" }
func (c *Client) pkceIndexKey() string  { return c.storageKey + "-flows-code-verifier" }
func (c *Client) pkceSlotKey(flowID string) string {
	return c.storageKey + "-flow-" + flowID + "-code-verifier"
}

// getJSONString reads key and decodes it as a JSON string, the format
// auth-js writes. Missing or malformed values yield "".
func (c *Client) getJSONString(ctx context.Context, key string) (string, error) {
	raw, err := c.storage.GetItem(ctx, key)
	if err != nil || raw == "" {
		return "", err
	}
	var v string
	if json.Unmarshal([]byte(raw), &v) != nil {
		return "", nil
	}
	return v, nil
}

func (c *Client) setJSON(ctx context.Context, key string, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return c.storage.SetItem(ctx, key, string(data))
}

// pkceIndex returns the ids of pending verifier slots, oldest first. Index
// entries are validated like URL-provided ids since shared storage (e.g.
// cookies) is no more trustworthy than a URL.
func (c *Client) pkceIndex(ctx context.Context) []string {
	raw, err := c.storage.GetItem(ctx, c.pkceIndexKey())
	if err != nil || raw == "" {
		return nil
	}
	var ids []string
	if json.Unmarshal([]byte(raw), &ids) != nil {
		return nil
	}
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if validPKCEFlowID(id) != "" {
			out = append(out, id)
		}
	}
	return out
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("auth: generate random bytes: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// pkceChallenge returns the S256 code challenge for a PKCE code verifier:
// base64url(sha256(verifier)) without padding (RFC 7636 section 4.2).
func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// pkceFlow is a started PKCE flow.
type pkceFlow struct {
	challenge string
	method    string
	flowID    string
}

// startPKCE generates a verifier, stores it in a new flow slot (and in the
// legacy fixed key), and returns the challenge to send.
func (c *Client) startPKCE(ctx context.Context, passwordRecovery bool) (*pkceFlow, error) {
	// 56 random bytes as hex = 112 characters, the same length auth-js uses
	// and within RFC 7636's 43..128 range.
	verifier, err := randomHex(56)
	if err != nil {
		return nil, err
	}
	flowID, err := randomHex(16)
	if err != nil {
		return nil, err
	}
	stored := verifier
	if passwordRecovery {
		stored += "/recovery"
	}

	c.pkceMu.Lock()
	defer c.pkceMu.Unlock()
	if err := c.setJSON(ctx, c.pkceSlotKey(flowID), stored); err != nil {
		return nil, fmt.Errorf("auth: store code verifier: %w", err)
	}
	index := c.pkceIndex(ctx)
	kept := make([]string, 0, len(index)+1)
	for _, id := range index {
		if id != flowID {
			kept = append(kept, id)
		}
	}
	kept = append(kept, flowID)
	for len(kept) > pkceMaxConcurrentFlows {
		_ = c.storage.RemoveItem(ctx, c.pkceSlotKey(kept[0]))
		kept = kept[1:]
	}
	if err := c.setJSON(ctx, c.pkceIndexKey(), kept); err != nil {
		return nil, fmt.Errorf("auth: store code verifier: %w", err)
	}
	// The legacy fixed key mirrors the most recent flow for exchanges that
	// cannot identify their flow.
	if err := c.setJSON(ctx, c.pkceLegacyKey(), stored); err != nil {
		return nil, fmt.Errorf("auth: store code verifier: %w", err)
	}
	return &pkceFlow{challenge: pkceChallenge(verifier), method: "s256", flowID: flowID}, nil
}

// maybeStartPKCE starts a flow when FlowType is PKCE, else returns nil.
func (c *Client) maybeStartPKCE(ctx context.Context, passwordRecovery bool) (*pkceFlow, error) {
	if c.cfg.FlowType != FlowPKCE {
		return nil, nil
	}
	return c.startPKCE(ctx, passwordRecovery)
}

// retrievePKCEVerifier returns the stored verifier for flowID. With a flow
// id only that slot is consulted (never another flow's verifier, which
// would burn the single-use code); without one the legacy key is read.
func (c *Client) retrievePKCEVerifier(ctx context.Context, flowID string) (string, error) {
	if flowID != "" {
		return c.getJSONString(ctx, c.pkceSlotKey(flowID))
	}
	return c.getJSONString(ctx, c.pkceLegacyKey())
}

// removePKCEVerifier removes one flow's verifier (or only the legacy key
// when flowID is ""), never other pending flows.
func (c *Client) removePKCEVerifier(ctx context.Context, flowID string) {
	c.pkceMu.Lock()
	defer c.pkceMu.Unlock()
	if flowID == "" {
		// The legacy key mirrors the most recent flow: remove that flow's
		// slot and index entry too, so nothing is left behind.
		legacy, _ := c.getJSONString(ctx, c.pkceLegacyKey())
		_ = c.storage.RemoveItem(ctx, c.pkceLegacyKey())
		if legacy == "" {
			return
		}
		index := c.pkceIndex(ctx)
		remaining := make([]string, 0, len(index))
		for _, id := range index {
			if v, _ := c.getJSONString(ctx, c.pkceSlotKey(id)); v == legacy {
				_ = c.storage.RemoveItem(ctx, c.pkceSlotKey(id))
				continue
			}
			remaining = append(remaining, id)
		}
		if len(remaining) != len(index) {
			if len(remaining) > 0 {
				_ = c.setJSON(ctx, c.pkceIndexKey(), remaining)
			} else {
				_ = c.storage.RemoveItem(ctx, c.pkceIndexKey())
			}
		}
		return
	}
	slotValue, _ := c.getJSONString(ctx, c.pkceSlotKey(flowID))
	_ = c.storage.RemoveItem(ctx, c.pkceSlotKey(flowID))
	index := c.pkceIndex(ctx)
	remaining := make([]string, 0, len(index))
	for _, id := range index {
		if id != flowID {
			remaining = append(remaining, id)
		}
	}
	if len(remaining) != len(index) {
		if len(remaining) > 0 {
			_ = c.setJSON(ctx, c.pkceIndexKey(), remaining)
		} else {
			_ = c.storage.RemoveItem(ctx, c.pkceIndexKey())
		}
	}
	if slotValue != "" {
		if legacy, _ := c.getJSONString(ctx, c.pkceLegacyKey()); legacy == slotValue {
			_ = c.storage.RemoveItem(ctx, c.pkceLegacyKey())
		}
	}
}

// removeAllPKCEVerifiers removes every pending verifier, the index and the
// legacy key (used on session teardown).
func (c *Client) removeAllPKCEVerifiers(ctx context.Context) {
	c.pkceMu.Lock()
	defer c.pkceMu.Unlock()
	for _, id := range c.pkceIndex(ctx) {
		_ = c.storage.RemoveItem(ctx, c.pkceSlotKey(id))
	}
	_ = c.storage.RemoveItem(ctx, c.pkceIndexKey())
	_ = c.storage.RemoveItem(ctx, c.pkceLegacyKey())
}

// redirectWithFlowID appends sb_flow_id to redirectTo when enabled by
// Config.AppendPKCEFlowIDToRedirects.
func (c *Client) redirectWithFlowID(redirectTo string, flow *pkceFlow) string {
	if redirectTo == "" || flow == nil || !c.cfg.AppendPKCEFlowIDToRedirects {
		return redirectTo
	}
	return appendFlowIDToRedirect(redirectTo, flow.flowID)
}

// appendFlowIDToRedirect sets the sb_flow_id parameter of redirectTo,
// replacing any existing one. It is string based so custom schemes and the
// app's own query encoding survive; a fragment stays last.
func appendFlowIDToRedirect(redirectTo, flowID string) string {
	base, fragment := redirectTo, ""
	if i := strings.IndexByte(redirectTo, '#'); i >= 0 {
		base, fragment = redirectTo[:i], redirectTo[i:]
	}
	if i := strings.IndexByte(base, '?'); i >= 0 {
		path := base[:i]
		var kept []string
		for _, pair := range strings.Split(base[i+1:], "&") {
			if pair == "" || pair == PKCEFlowIDParam || strings.HasPrefix(pair, PKCEFlowIDParam+"=") {
				continue
			}
			kept = append(kept, pair)
		}
		base = path
		if len(kept) > 0 {
			base += "?" + strings.Join(kept, "&")
		}
	}
	sep := "?"
	if strings.Contains(base, "?") {
		sep = "&"
	}
	return base + sep + PKCEFlowIDParam + "=" + encodeURIComponent(flowID) + fragment
}

// flowChallenge returns the code_challenge fields to embed in a body; both
// are nil (JSON null, as auth-js sends) when flow is nil.
func flowChallenge(flow *pkceFlow) (challenge, method *string) {
	if flow == nil {
		return nil, nil
	}
	return &flow.challenge, &flow.method
}

func flowIDOf(flow *pkceFlow) string {
	if flow == nil {
		return ""
	}
	return flow.flowID
}

package realtime

import (
	"bytes"
	"encoding/json"
	"sort"
)

// Presence is one tracked presence of a key (upstream Presence<T>): the
// payload passed to Track plus the server-assigned presence_ref.
type Presence struct {
	// Ref is the presence_ref (phoenix phx_ref) identifying this presence.
	Ref string
	// Payload holds the tracked fields.
	Payload map[string]json.RawMessage
}

// MarshalJSON encodes the presence as realtime-js exposes it: the tracked
// fields plus "presence_ref".
func (p Presence) MarshalJSON() ([]byte, error) {
	m := make(map[string]json.RawMessage, len(p.Payload)+1)
	for k, v := range p.Payload {
		m[k] = v
	}
	ref, err := json.Marshal(p.Ref)
	if err != nil {
		return nil, err
	}
	m["presence_ref"] = ref
	return json.Marshal(m)
}

// UnmarshalJSON decodes the form produced by MarshalJSON.
func (p *Presence) UnmarshalJSON(data []byte) error {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}
	p.Ref = ""
	if r, ok := m["presence_ref"]; ok {
		if err := json.Unmarshal(r, &p.Ref); err != nil {
			return err
		}
		delete(m, "presence_ref")
	}
	p.Payload = m
	return nil
}

// Decode unmarshals the presence (fields plus presence_ref) into v.
func (p Presence) Decode(v any) error {
	b, err := p.MarshalJSON()
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// PresenceState maps presence keys to their presences (upstream
// RealtimePresenceState).
type PresenceState map[string][]Presence

// PresenceJoinEvent is delivered to OnPresenceJoin callbacks.
type PresenceJoinEvent struct {
	Key string
	// CurrentPresences are the key's presences before the join.
	CurrentPresences []Presence
	// NewPresences are the joining presences.
	NewPresences []Presence
}

// PresenceLeaveEvent is delivered to OnPresenceLeave callbacks.
type PresenceLeaveEvent struct {
	Key string
	// CurrentPresences are the key's presences remaining after the leave.
	CurrentPresences []Presence
	// LeftPresences are the leaving presences.
	LeftPresences []Presence
}

// presenceMeta is one raw phoenix presence meta (contains phx_ref).
type presenceMeta map[string]json.RawMessage

func (m presenceMeta) ref() string {
	var s string
	if raw, ok := m["phx_ref"]; ok {
		if json.Unmarshal(raw, &s) != nil {
			s = string(bytes.TrimSpace(raw))
		}
	}
	return s
}

type presenceEntry struct {
	Metas []presenceMeta `json:"metas"`
}

func (e *presenceEntry) clone() *presenceEntry {
	if e == nil {
		return nil
	}
	out := &presenceEntry{Metas: make([]presenceMeta, len(e.Metas))}
	for i, m := range e.Metas {
		c := make(presenceMeta, len(m))
		for k, v := range m {
			c[k] = v
		}
		out.Metas[i] = c
	}
	return out
}

func (e *presenceEntry) refs() map[string]bool {
	r := make(map[string]bool, len(e.Metas))
	for _, m := range e.Metas {
		r[m.ref()] = true
	}
	return r
}

type presenceMap map[string]*presenceEntry

type presenceDiff struct {
	Joins  presenceMap `json:"joins"`
	Leaves presenceMap `json:"leaves"`
}

// presenceTracker mirrors phoenix Presence. Requires client.mu.
type presenceTracker struct {
	ch           *Channel
	state        presenceMap
	pendingDiffs []presenceDiff
	joinRef      string
}

func (t *presenceTracker) onState(raw json.RawMessage) {
	var newState presenceMap
	if err := json.Unmarshal(raw, &newState); err != nil {
		return
	}
	t.joinRef = t.ch.joinRef()
	t.state = syncState(t.state, newState, t.onJoin, t.onLeave)
	for _, d := range t.pendingDiffs {
		t.state = syncDiff(t.state, d, t.onJoin, t.onLeave)
	}
	t.pendingDiffs = nil
	t.ch.dispatchPresence("sync", nil, nil)
}

func (t *presenceTracker) onDiff(raw json.RawMessage) {
	var diff presenceDiff
	if err := json.Unmarshal(raw, &diff); err != nil {
		return
	}
	if t.inPendingSyncState() {
		t.pendingDiffs = append(t.pendingDiffs, diff)
		return
	}
	t.state = syncDiff(t.state, diff, t.onJoin, t.onLeave)
	t.ch.dispatchPresence("sync", nil, nil)
}

func (t *presenceTracker) inPendingSyncState() bool {
	return t.joinRef == "" || t.joinRef != t.ch.joinRef()
}

func (t *presenceTracker) onJoin(key string, current, joined *presenceEntry) {
	ev := PresenceJoinEvent{Key: key, CurrentPresences: transformPresences(current), NewPresences: transformPresences(joined)}
	t.ch.dispatchPresence("join", &ev, nil)
}

func (t *presenceTracker) onLeave(key string, current, left *presenceEntry) {
	ev := PresenceLeaveEvent{Key: key, CurrentPresences: transformPresences(current), LeftPresences: transformPresences(left)}
	t.ch.dispatchPresence("leave", nil, &ev)
}

func (t *presenceTracker) snapshot() PresenceState {
	out := make(PresenceState, len(t.state))
	for k, e := range t.state {
		out[k] = transformPresences(e)
	}
	return out
}

// transformPresences renames phx_ref to presence_ref and drops phx_ref_prev
// (RealtimePresence.transformState). It always returns a deep copy.
func transformPresences(e *presenceEntry) []Presence {
	out := []Presence{}
	if e == nil {
		return out
	}
	for _, m := range e.Metas {
		p := Presence{Ref: m.ref(), Payload: make(map[string]json.RawMessage, len(m))}
		for k, v := range m {
			if k == "phx_ref" || k == "phx_ref_prev" {
				continue
			}
			p.Payload[k] = append(json.RawMessage(nil), v...)
		}
		out = append(out, p)
	}
	return out
}

func sortedKeys(m presenceMap) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

type presenceCallback func(key string, current, changed *presenceEntry)

// syncState mirrors phoenix Presence.syncState.
func syncState(current, newState presenceMap, onJoin, onLeave presenceCallback) presenceMap {
	state := make(presenceMap, len(current))
	for k, v := range current {
		state[k] = v.clone()
	}
	joins, leaves := presenceMap{}, presenceMap{}
	for _, key := range sortedKeys(state) {
		if newState[key] == nil {
			leaves[key] = state[key]
		}
	}
	for _, key := range sortedKeys(newState) {
		newP := newState[key]
		if newP == nil {
			continue
		}
		cur := state[key]
		if cur == nil {
			joins[key] = newP
			continue
		}
		newRefs, curRefs := newP.refs(), cur.refs()
		var joined, left []presenceMeta
		for _, m := range newP.Metas {
			if !curRefs[m.ref()] {
				joined = append(joined, m)
			}
		}
		for _, m := range cur.Metas {
			if !newRefs[m.ref()] {
				left = append(left, m)
			}
		}
		if len(joined) > 0 {
			joins[key] = &presenceEntry{Metas: joined}
		}
		if len(left) > 0 {
			l := cur.clone()
			l.Metas = left
			leaves[key] = l
		}
	}
	return syncDiff(state, presenceDiff{Joins: joins, Leaves: leaves}, onJoin, onLeave)
}

// syncDiff mirrors phoenix Presence.syncDiff. It mutates and returns state.
func syncDiff(state presenceMap, diff presenceDiff, onJoin, onLeave presenceCallback) presenceMap {
	if state == nil {
		state = presenceMap{}
	}
	joins, leaves := presenceMap{}, presenceMap{}
	for k, v := range diff.Joins {
		if v != nil {
			joins[k] = v.clone()
		}
	}
	for k, v := range diff.Leaves {
		if v != nil {
			leaves[k] = v.clone()
		}
	}
	for _, key := range sortedKeys(joins) {
		newP := joins[key]
		cur := state[key]
		next := newP.clone()
		if cur != nil {
			joinedRefs := next.refs()
			var curMetas []presenceMeta
			for _, m := range cur.Metas {
				if !joinedRefs[m.ref()] {
					curMetas = append(curMetas, m)
				}
			}
			next.Metas = append(curMetas, next.Metas...)
		}
		state[key] = next
		if onJoin != nil {
			onJoin(key, cur, newP)
		}
	}
	for _, key := range sortedKeys(leaves) {
		left := leaves[key]
		cur := state[key]
		if cur == nil {
			continue
		}
		remove := left.refs()
		kept := cur.Metas[:0:0]
		for _, m := range cur.Metas {
			if !remove[m.ref()] {
				kept = append(kept, m)
			}
		}
		cur.Metas = kept
		if onLeave != nil {
			onLeave(key, cur, left)
		}
		if len(cur.Metas) == 0 {
			delete(state, key)
		}
	}
	return state
}

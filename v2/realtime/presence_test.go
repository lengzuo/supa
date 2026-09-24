package realtime

import (
	"encoding/json"
	"reflect"
	"testing"
)

// upstream: realtime-js test/RealtimeChannel.presence.test.ts (join/leave/sync, pending diffs, presenceState)
func TestPresenceEvents(t *testing.T) {
	fs := newFakeServer(t)
	c := newTestClient(t, fs, nil)
	joins := make(chan PresenceJoinEvent, 8)
	leaves := make(chan PresenceLeaveEvent, 8)
	syncs := make(chan struct{}, 8)
	ch, sc, join := subscribeJoined(t, c, fs, "presence", ChannelOptions{Presence: PresenceOptions{Key: "me"}}, func(ch *Channel) {
		_ = ch.OnPresenceJoin(func(e PresenceJoinEvent) { joins <- e })
		_ = ch.OnPresenceLeave(func(e PresenceLeaveEvent) { leaves <- e })
		_ = ch.OnPresenceSync(func() { syncs <- struct{}{} })
	})
	cfg := sc.config("realtime:presence")
	if p, _ := cfg["presence"].(map[string]any); p["enabled"] != true || p["key"] != "me" {
		t.Fatalf("presence config = %v", cfg["presence"])
	}
	if got := ch.PresenceState(); len(got) != 0 {
		t.Fatalf("initial state = %v", got)
	}

	// A diff before the initial state is buffered.
	sc.send(join.ref(), nil, "realtime:presence", "presence_diff", map[string]any{
		"joins":  map[string]any{"user-123": map[string]any{"metas": []any{map[string]any{"phx_ref": "r1", "name": "John"}}}},
		"leaves": map[string]any{},
	})
	select {
	case <-joins:
		t.Fatal("diff processed before presence_state")
	default:
	}
	sc.send(join.ref(), nil, "realtime:presence", "presence_state", map[string]any{})
	j := recv(t, joins, "join")
	if j.Key != "user-123" || len(j.CurrentPresences) != 0 || len(j.NewPresences) != 1 || j.NewPresences[0].Ref != "r1" {
		t.Fatalf("join = %+v", j)
	}
	recv(t, syncs, "sync")

	st := ch.PresenceState()
	b, _ := json.Marshal(st)
	if string(b) != `{"user-123":[{"name":"John","presence_ref":"r1"}]}` {
		t.Fatalf("state = %s", b)
	}
	var decoded struct {
		Name string `json:"name"`
		Ref  string `json:"presence_ref"`
	}
	if err := st["user-123"][0].Decode(&decoded); err != nil || decoded.Name != "John" || decoded.Ref != "r1" {
		t.Fatalf("Decode = %+v %v", decoded, err)
	}

	// Second device joins for the same key, then first leaves.
	sc.send(join.ref(), nil, "realtime:presence", "presence_diff", map[string]any{
		"joins":  map[string]any{"user-123": map[string]any{"metas": []any{map[string]any{"phx_ref": "r2", "phx_ref_prev": "r0", "name": "John2"}}}},
		"leaves": map[string]any{},
	})
	j = recv(t, joins, "second join")
	if len(j.CurrentPresences) != 1 || j.CurrentPresences[0].Ref != "r1" || j.NewPresences[0].Ref != "r2" {
		t.Fatalf("second join = %+v", j)
	}
	if _, ok := j.NewPresences[0].Payload["phx_ref_prev"]; ok {
		t.Fatal("phx_ref_prev not removed")
	}
	recv(t, syncs, "sync")
	sc.send(join.ref(), nil, "realtime:presence", "presence_diff", map[string]any{
		"joins":  map[string]any{},
		"leaves": map[string]any{"user-123": map[string]any{"metas": []any{map[string]any{"phx_ref": "r1", "name": "John"}}}},
	})
	l := recv(t, leaves, "leave")
	if l.Key != "user-123" || len(l.LeftPresences) != 1 || l.LeftPresences[0].Ref != "r1" ||
		len(l.CurrentPresences) != 1 || l.CurrentPresences[0].Ref != "r2" {
		t.Fatalf("leave = %+v", l)
	}
	recv(t, syncs, "sync")
	if st := ch.PresenceState(); len(st["user-123"]) != 1 || st["user-123"][0].Ref != "r2" {
		t.Fatalf("state = %+v", st)
	}
}

// upstream: realtime-js test/RealtimeChannel.presence.test.ts track / untrack
func TestPresenceTrackUntrack(t *testing.T) {
	fs := newFakeServer(t)
	c := newTestClient(t, fs, nil)
	ch, sc, _ := subscribeJoined(t, c, fs, "presence", ChannelOptions{}, nil)
	if cfg := sc.config("realtime:presence"); cfg["presence"].(map[string]any)["enabled"] != false {
		t.Fatalf("presence should be disabled without callbacks: %v", cfg)
	}
	if err := ch.Track(ctxT(t), map[string]string{"online_at": "now"}); err != nil {
		t.Fatalf("Track: %v", err)
	}
	m := sc.expectEvent(t, "realtime:presence", "presence")
	if string(m.Payload) != `{"type":"presence","event":"track","payload":{"online_at":"now"}}` {
		t.Fatalf("track = %s", m.Payload)
	}
	if err := ch.Untrack(ctxT(t)); err != nil {
		t.Fatalf("Untrack: %v", err)
	}
	m = sc.expectEvent(t, "realtime:presence", "presence")
	if string(m.Payload) != `{"type":"presence","event":"untrack"}` {
		t.Fatalf("untrack = %s", m.Payload)
	}
	// Track before subscribe fails.
	other, _ := c.Channel("other", ChannelOptions{})
	if err := other.Track(ctxT(t), map[string]int{}); err == nil {
		t.Fatal("Track before Subscribe must fail")
	}
}

func meta(ref string, extra ...string) presenceMeta {
	m := presenceMeta{"phx_ref": json.RawMessage(`"` + ref + `"`)}
	for i := 0; i+1 < len(extra); i += 2 {
		m[extra[i]] = json.RawMessage(extra[i+1])
	}
	return m
}

func refsOf(e *presenceEntry) []string {
	if e == nil {
		return nil
	}
	var out []string
	for _, m := range e.Metas {
		out = append(out, m.ref())
	}
	return out
}

// upstream: phoenix assets/test/presence_test.js syncState
func TestPresenceSyncState(t *testing.T) {
	var joined, left []string
	onJoin := func(key string, cur, n *presenceEntry) { joined = append(joined, key+":"+refsOf(n)[0]) }
	onLeave := func(key string, cur, l *presenceEntry) { left = append(left, key+":"+refsOf(l)[0]) }

	state := syncState(nil, presenceMap{"u1": {Metas: []presenceMeta{meta("1")}}}, onJoin, onLeave)
	if !reflect.DeepEqual(joined, []string{"u1:1"}) || len(left) != 0 {
		t.Fatalf("joins=%v leaves=%v", joined, left)
	}
	joined, left = nil, nil
	// u1 changes device (ref 1 -> 2), u2 joins, nothing else.
	newState := presenceMap{
		"u1": {Metas: []presenceMeta{meta("2")}},
		"u2": {Metas: []presenceMeta{meta("3")}},
	}
	before := state["u1"]
	state = syncState(state, newState, onJoin, onLeave)
	if !reflect.DeepEqual(joined, []string{"u1:2", "u2:3"}) || !reflect.DeepEqual(left, []string{"u1:1"}) {
		t.Fatalf("joins=%v leaves=%v", joined, left)
	}
	if !reflect.DeepEqual(refsOf(state["u1"]), []string{"2"}) || !reflect.DeepEqual(refsOf(state["u2"]), []string{"3"}) {
		t.Fatalf("state = %v / %v", refsOf(state["u1"]), refsOf(state["u2"]))
	}
	if !reflect.DeepEqual(refsOf(before), []string{"1"}) {
		t.Fatal("syncState mutated the previous state")
	}
	joined, left = nil, nil
	// Everyone leaves.
	state = syncState(state, presenceMap{}, onJoin, onLeave)
	if len(state) != 0 || !reflect.DeepEqual(left, []string{"u1:2", "u2:3"}) {
		t.Fatalf("state=%v leaves=%v", state, left)
	}
}

// upstream: phoenix assets/test/presence_test.js syncDiff
func TestPresenceSyncDiff(t *testing.T) {
	state := syncDiff(nil, presenceDiff{Joins: presenceMap{"u1": {Metas: []presenceMeta{meta("1")}}}}, nil, nil)
	// Join with an existing ref replaces it; new refs append after current.
	state = syncDiff(state, presenceDiff{Joins: presenceMap{"u1": {Metas: []presenceMeta{meta("2", "x", "1")}}}}, nil, nil)
	if !reflect.DeepEqual(refsOf(state["u1"]), []string{"1", "2"}) {
		t.Fatalf("refs = %v", refsOf(state["u1"]))
	}
	var leftCur []string
	state = syncDiff(state, presenceDiff{Leaves: presenceMap{
		"u1":      {Metas: []presenceMeta{meta("1")}},
		"missing": {Metas: []presenceMeta{meta("9")}},
	}}, nil, func(key string, cur, l *presenceEntry) { leftCur = refsOf(cur) })
	if !reflect.DeepEqual(refsOf(state["u1"]), []string{"2"}) || !reflect.DeepEqual(leftCur, []string{"2"}) {
		t.Fatalf("after leave refs = %v cur=%v", refsOf(state["u1"]), leftCur)
	}
	state = syncDiff(state, presenceDiff{Leaves: presenceMap{"u1": {Metas: []presenceMeta{meta("2")}}}}, nil, nil)
	if _, ok := state["u1"]; ok {
		t.Fatal("empty key not removed")
	}
}

func TestPresenceJSON(t *testing.T) {
	var p Presence
	if err := json.Unmarshal([]byte(`{"presence_ref":"r","a":1}`), &p); err != nil || p.Ref != "r" || string(p.Payload["a"]) != "1" {
		t.Fatalf("unmarshal = %+v %v", p, err)
	}
	b, _ := json.Marshal(p)
	if string(b) != `{"a":1,"presence_ref":"r"}` {
		t.Fatalf("marshal = %s", b)
	}
}

package realtime

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// upstream: realtime-js test/serializer.test.ts JSON encode/decode
func TestSerializerJSON(t *testing.T) {
	s := serializer{vsn: VSN2}
	f, err := s.encode(outMessage{JoinRef: "0", Ref: "1", Topic: "t", Event: "e", Payload: map[string]int{"foo": 1}})
	if err != nil || f.typ != MessageText || string(f.data) != `["0","1","t","e",{"foo":1}]` {
		t.Fatalf("encode = %s, %v", f.data, err)
	}
	f, _ = s.encode(outMessage{Topic: "t", Event: "e", Payload: map[string]int{"foo": 1}})
	if string(f.data) != `[null,null,"t","e",{"foo":1}]` {
		t.Fatalf("encode missing refs = %s", f.data)
	}
	m, err := s.decode(MessageText, []byte(`["0","1","t","e",{"foo":1}]`))
	if err != nil || m.JoinRef != "0" || m.Ref != "1" || m.Topic != "t" || m.Event != "e" || string(m.Payload) != `{"foo":1}` {
		t.Fatalf("decode = %+v, %v", m, err)
	}
	m, err = s.decode(MessageText, []byte(`[null,null,"t","e",{"foo":1}]`))
	if err != nil || m.JoinRef != "" || m.Ref != "" {
		t.Fatalf("decode missing refs = %+v, %v", m, err)
	}

	v1 := serializer{vsn: VSN1}
	f, _ = v1.encode(outMessage{JoinRef: "0", Ref: "1", Topic: "t", Event: "e", Payload: map[string]int{"foo": 1}})
	if string(f.data) != `{"topic":"t","event":"e","payload":{"foo":1},"ref":"1","join_ref":"0"}` {
		t.Fatalf("vsn1 encode = %s", f.data)
	}
	m, err = v1.decode(MessageText, f.data)
	if err != nil || m.JoinRef != "0" || m.Ref != "1" || m.Topic != "t" || string(m.Payload) != `{"foo":1}` {
		t.Fatalf("vsn1 decode = %+v %v", m, err)
	}

	for _, bad := range []string{`nope`, `["0","1"]`, `[1,"1","t","e",{}]`} {
		if _, err := s.decode(MessageText, []byte(bad)); err == nil {
			t.Errorf("decode(%s) succeeded", bad)
		}
	}
}

// upstream: realtime-js test/serializer.test.ts binary user broadcast push encoding
func TestSerializerBinaryUserBroadcastPush(t *testing.T) {
	s := serializer{vsn: VSN2}
	args := &sendArgs{Type: "broadcast", Event: "user-event", Payload: json.RawMessage(`{"a":"b"}`), hasPayload: true}
	f, err := s.encode(outMessage{JoinRef: "10", Ref: "1", Topic: "top", Event: "broadcast", Payload: args})
	if err != nil {
		t.Fatal(err)
	}
	want := "\x03\x02\x01\x03\x0a\x00\x01101topuser-event{\"a\":\"b\"}"
	if f.typ != MessageBinary || string(f.data) != want {
		t.Fatalf("encode = %q", f.data)
	}

	// Non-ASCII event: lengths are UTF-8 byte counts.
	ev := "café-🎉"
	f, _ = s.encode(outMessage{JoinRef: "10", Ref: "1", Topic: "top", Event: "broadcast", Payload: &sendArgs{Type: "broadcast", Event: ev, Payload: json.RawMessage(`{}`), hasPayload: true}})
	if int(f.data[4]) != len(ev) || string(f.data[7+2+1+3:7+2+1+3+len(ev)]) != ev {
		t.Fatalf("utf-8 event encoding = %q", f.data)
	}

	// Binary payload and missing payload.
	f, _ = s.encode(outMessage{JoinRef: "1", Ref: "2", Topic: "t", Event: "broadcast", Payload: &sendArgs{Type: "broadcast", Event: "e", Payload: []byte{1, 4}, hasPayload: true}})
	if f.data[6] != binEncodingBinary || !bytes.HasSuffix(f.data, []byte{'e', 1, 4}) {
		t.Fatalf("binary payload = %v", f.data)
	}
	f, _ = s.encode(outMessage{JoinRef: "1", Ref: "2", Topic: "t", Event: "broadcast", Payload: &sendArgs{Type: "broadcast", Event: "e"}})
	if !bytes.HasSuffix(f.data, []byte("e{}")) {
		t.Fatalf("empty payload = %q", f.data)
	}

	// Oversized fields are rejected.
	long := strings.Repeat("x", 256)
	if _, err := s.encode(outMessage{Topic: long, Event: "broadcast", Payload: &sendArgs{Event: "e"}}); err == nil {
		t.Fatal("expected error for topic > 255 bytes")
	}
	if _, err := s.encode(outMessage{Topic: "t", Event: "broadcast", Payload: &sendArgs{Event: long}}); err == nil {
		t.Fatal("expected error for event > 255 bytes")
	}

	// VSN1 never uses binary frames.
	f, _ = serializer{vsn: VSN1}.encode(outMessage{Ref: "1", Topic: "t", Event: "broadcast", Payload: args})
	if f.typ != MessageText || string(f.data) != `{"topic":"t","event":"broadcast","payload":{"type":"broadcast","event":"user-event","payload":{"a":"b"}},"ref":"1","join_ref":null}` {
		t.Fatalf("vsn1 broadcast = %s", f.data)
	}
}

// upstream: realtime-js test/serializer.test.ts binary user broadcast decoding
func TestSerializerBinaryDecode(t *testing.T) {
	s := serializer{vsn: VSN2}
	frame := []byte("\x04\x03\x0a\x00\x01topuser-event{\"a\":\"b\"}")
	m, err := s.decode(MessageBinary, frame)
	if err != nil {
		t.Fatal(err)
	}
	if m.Topic != "top" || m.Event != "broadcast" || m.JoinRef != "" || m.Ref != "" {
		t.Fatalf("decoded = %+v", m)
	}
	if string(m.Payload) != `{"event":"user-event","payload":{"a":"b"},"type":"broadcast"}` {
		t.Fatalf("payload = %s", m.Payload)
	}
	withMeta := []byte("\x04\x03\x0a\x0d\x01topuser-event{\"id\":\"meta\"}{\"a\":\"b\"}")
	m, err = s.decode(MessageBinary, withMeta)
	if err != nil || !strings.Contains(string(m.Payload), `"meta":{"id":"meta"}`) {
		t.Fatalf("meta decode = %s, %v", m.Payload, err)
	}
	raw := []byte("\x04\x03\x0a\x00\x00topuser-event\x01\x04")
	m, err = s.decode(MessageBinary, raw)
	if err != nil || !bytes.Equal(m.Binary, []byte{1, 4}) || strings.Contains(string(m.Payload), `"payload"`) {
		t.Fatalf("binary decode = %+v, %v", m, err)
	}
	for _, bad := range [][]byte{nil, {4}, {4, 10, 0, 0, 1, 'x'}, {9, 0, 0, 0, 0}, []byte("\x04\x01\x01\x00\x01te{bad")} {
		if _, err := s.decode(MessageBinary, bad); err == nil {
			t.Errorf("decode(%q) succeeded", bad)
		}
	}
}

func TestJoinObjectValues(t *testing.T) {
	cases := map[string]string{
		`{"reason":"Unauthorized"}`: "Unauthorized",
		`{"a":"x","b":2,"c":null}`:  "x, 2, ",
		`"plain"`:                   "plain",
		`null`:                      "",
		`{}`:                        "",
	}
	for in, want := range cases {
		if got := joinObjectValues(json.RawMessage(in)); got != want {
			t.Errorf("joinObjectValues(%s) = %q, want %q", in, got, want)
		}
	}
}

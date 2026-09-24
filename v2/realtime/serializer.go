package realtime

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"unicode/utf8"
)

// Protocol versions ("vsn") understood by the Realtime server.
const (
	// VSN1 is the JSON object protocol (vsn=1.0.0).
	VSN1 = "1.0.0"
	// VSN2 is the JSON array protocol with binary user broadcasts
	// (vsn=2.0.0). It is the default, matching realtime-js.
	VSN2 = "2.0.0"
	// DefaultVSN is the protocol version used when Config.VSN is empty.
	DefaultVSN = VSN2
)

// Binary frame layout constants (realtime-js src/lib/serializer.ts).
const (
	binHeaderLength             = 1
	binUserBroadcastPushMetaLen = 6
	binKindUserBroadcastPush    = 3
	binKindUserBroadcast        = 4
	binEncodingBinary           = 0
	binEncodingJSON             = 1
	eventBroadcast              = "broadcast"
)

// outMessage is a message to be written to the socket. Empty JoinRef/Ref
// are encoded as JSON null.
type outMessage struct {
	JoinRef string
	Ref     string
	Topic   string
	Event   string
	Payload any
}

// inMessage is a decoded message received from the socket.
type inMessage struct {
	JoinRef string
	Ref     string
	Topic   string
	Event   string
	Payload json.RawMessage
	// Binary holds the raw user payload of a binary-encoded broadcast.
	Binary []byte
}

// frame is an encoded websocket message.
type frame struct {
	typ  MessageType
	data []byte
}

// sendArgs is the payload of a channel push created by Channel.Send
// ({type, event, payload}). Payload is json.RawMessage or []byte.
type sendArgs struct {
	Type       string
	Event      string
	Payload    any
	hasPayload bool
}

// MarshalJSON encodes the args as {"type":..,"event":..,"payload":..}.
func (a *sendArgs) MarshalJSON() ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteString(`{"type":`)
	t, _ := json.Marshal(a.Type)
	buf.Write(t)
	buf.WriteString(`,"event":`)
	e, _ := json.Marshal(a.Event)
	buf.Write(e)
	if a.hasPayload {
		buf.WriteString(`,"payload":`)
		p, err := json.Marshal(a.Payload)
		if err != nil {
			return nil, err
		}
		buf.Write(p)
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

// serializer encodes and decodes Phoenix messages for one protocol version.
type serializer struct {
	vsn string
}

func nullableString(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// encode encodes msg for the wire.
func (s serializer) encode(msg outMessage) (frame, error) {
	if s.vsn == VSN1 {
		// JSON.stringify({topic, event, payload, ref, join_ref})
		data, err := json.Marshal(struct {
			Topic   string `json:"topic"`
			Event   string `json:"event"`
			Payload any    `json:"payload"`
			Ref     any    `json:"ref"`
			JoinRef any    `json:"join_ref"`
		}{msg.Topic, msg.Event, msg.Payload, nullableString(msg.Ref), nullableString(msg.JoinRef)})
		if err != nil {
			return frame{}, fmt.Errorf("realtime: encode message: %w", err)
		}
		return frame{typ: MessageText, data: data}, nil
	}
	if args, ok := msg.Payload.(*sendArgs); ok && msg.Event == eventBroadcast {
		data, err := encodeUserBroadcastPush(msg, args)
		if err != nil {
			return frame{}, err
		}
		return frame{typ: MessageBinary, data: data}, nil
	}
	data, err := json.Marshal([]any{nullableString(msg.JoinRef), nullableString(msg.Ref), msg.Topic, msg.Event, msg.Payload})
	if err != nil {
		return frame{}, fmt.Errorf("realtime: encode message: %w", err)
	}
	return frame{typ: MessageText, data: data}, nil
}

// encodeUserBroadcastPush builds a kind-3 binary frame:
//
//	kind | joinRefLen | refLen | topicLen | eventLen | metaLen | encoding |
//	joinRef | ref | topic | event | meta | payload
func encodeUserBroadcastPush(msg outMessage, args *sendArgs) ([]byte, error) {
	encoding := byte(binEncodingJSON)
	var payload []byte
	switch p := args.Payload.(type) {
	case []byte:
		encoding = binEncodingBinary
		payload = p
	case json.RawMessage:
		payload = p
	case nil:
		payload = []byte("{}")
	default:
		b, err := json.Marshal(p)
		if err != nil {
			return nil, fmt.Errorf("realtime: encode broadcast payload: %w", err)
		}
		payload = b
	}
	if !args.hasPayload || (encoding == binEncodingJSON && len(payload) == 0) {
		payload = []byte("{}")
	}
	fields := []struct {
		name string
		val  string
	}{
		{"joinRef", msg.JoinRef}, {"ref", msg.Ref}, {"topic", msg.Topic}, {"userEvent", args.Event},
	}
	for _, f := range fields {
		if len(f.val) > 255 {
			return nil, fmt.Errorf("realtime: %s length %d exceeds maximum of 255", f.name, len(f.val))
		}
	}
	out := make([]byte, 0, binHeaderLength+binUserBroadcastPushMetaLen+len(msg.JoinRef)+len(msg.Ref)+len(msg.Topic)+len(args.Event)+len(payload))
	out = append(out,
		binKindUserBroadcastPush,
		byte(len(msg.JoinRef)),
		byte(len(msg.Ref)),
		byte(len(msg.Topic)),
		byte(len(args.Event)),
		0, // metadata length: no metadata keys are forwarded
		encoding,
	)
	out = append(out, msg.JoinRef...)
	out = append(out, msg.Ref...)
	out = append(out, msg.Topic...)
	out = append(out, args.Event...)
	out = append(out, payload...)
	return out, nil
}

var errMalformedFrame = errors.New("realtime: malformed frame")

// decode decodes a websocket message.
func (s serializer) decode(typ MessageType, data []byte) (inMessage, error) {
	if typ == MessageBinary {
		return decodeBinary(data)
	}
	if s.vsn == VSN1 {
		var m struct {
			Topic   string          `json:"topic"`
			Event   string          `json:"event"`
			Payload json.RawMessage `json:"payload"`
			Ref     *string         `json:"ref"`
			JoinRef *string         `json:"join_ref"`
		}
		if err := json.Unmarshal(data, &m); err != nil {
			return inMessage{}, fmt.Errorf("realtime: decode message: %w", err)
		}
		return inMessage{JoinRef: deref(m.JoinRef), Ref: deref(m.Ref), Topic: m.Topic, Event: m.Event, Payload: m.Payload}, nil
	}
	var arr []json.RawMessage
	if err := json.Unmarshal(data, &arr); err != nil {
		return inMessage{}, fmt.Errorf("realtime: decode message: %w", err)
	}
	if len(arr) < 5 {
		return inMessage{}, errMalformedFrame
	}
	var joinRef, ref *string
	var topic, event string
	if err := json.Unmarshal(arr[0], &joinRef); err != nil {
		return inMessage{}, fmt.Errorf("realtime: decode join_ref: %w", err)
	}
	if err := json.Unmarshal(arr[1], &ref); err != nil {
		return inMessage{}, fmt.Errorf("realtime: decode ref: %w", err)
	}
	if err := json.Unmarshal(arr[2], &topic); err != nil {
		return inMessage{}, fmt.Errorf("realtime: decode topic: %w", err)
	}
	if err := json.Unmarshal(arr[3], &event); err != nil {
		return inMessage{}, fmt.Errorf("realtime: decode event: %w", err)
	}
	return inMessage{JoinRef: deref(joinRef), Ref: deref(ref), Topic: topic, Event: event, Payload: arr[4]}, nil
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// decodeBinary decodes a kind-4 user broadcast frame:
//
//	kind | topicLen | eventLen | metaLen | encoding | topic | event | meta | payload
func decodeBinary(data []byte) (inMessage, error) {
	if len(data) < 1 {
		return inMessage{}, errMalformedFrame
	}
	if data[0] != binKindUserBroadcast {
		return inMessage{}, fmt.Errorf("realtime: unsupported binary frame kind %d", data[0])
	}
	if len(data) < binHeaderLength+4 {
		return inMessage{}, errMalformedFrame
	}
	topicSize, eventSize, metaSize, encoding := int(data[1]), int(data[2]), int(data[3]), data[4]
	off := binHeaderLength + 4
	if len(data) < off+topicSize+eventSize+metaSize {
		return inMessage{}, errMalformedFrame
	}
	topic := string(data[off : off+topicSize])
	off += topicSize
	event := string(data[off : off+eventSize])
	off += eventSize
	meta := data[off : off+metaSize]
	off += metaSize
	payload := data[off:]

	if !utf8.ValidString(topic) || !utf8.ValidString(event) {
		return inMessage{}, errMalformedFrame
	}
	obj := map[string]json.RawMessage{}
	obj["type"], _ = json.Marshal(eventBroadcast)
	obj["event"], _ = json.Marshal(event)
	msg := inMessage{Topic: topic, Event: eventBroadcast}
	if encoding == binEncodingJSON {
		if !json.Valid(payload) {
			return inMessage{}, fmt.Errorf("realtime: invalid JSON broadcast payload")
		}
		obj["payload"] = append(json.RawMessage(nil), payload...)
	} else {
		msg.Binary = append([]byte(nil), payload...)
	}
	if metaSize > 0 {
		if !json.Valid(meta) {
			return inMessage{}, fmt.Errorf("realtime: invalid broadcast metadata")
		}
		obj["meta"] = append(json.RawMessage(nil), meta...)
	}
	p, err := json.Marshal(obj)
	if err != nil {
		return inMessage{}, err
	}
	msg.Payload = p
	return msg, nil
}

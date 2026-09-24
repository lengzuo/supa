package realtime

import (
	"encoding/json"
	"time"
)

// pushReply is a server reply ({status, response}) or a local outcome.
type pushReply struct {
	status   string
	response json.RawMessage
}

type pushHook struct {
	status string
	fn     func(json.RawMessage)
}

// push mirrors phoenix Push. All methods require Client.mu.
type push struct {
	ch       *Channel
	event    string
	payload  func() any
	timeout  time.Duration
	ref      string
	refEvent string
	received *pushReply
	timer    *ltimer
	hooks    []pushHook
	aborts   []func(error)
}

func newPush(ch *Channel, event string, payload func() any, timeout time.Duration) *push {
	if payload == nil {
		payload = func() any { return json.RawMessage("{}") }
	}
	return &push{ch: ch, event: event, payload: payload, timeout: timeout}
}

func (p *push) resend(timeout time.Duration) {
	p.timeout = timeout
	p.reset()
	p.send()
}

func (p *push) send() {
	if p.hasReceived("timeout") {
		return
	}
	p.startTimeout()
	p.ch.client.push(outMessage{
		Topic:   p.ch.topic,
		Event:   p.event,
		Payload: p.payload(),
		Ref:     p.ref,
		JoinRef: p.ch.joinRef(),
	})
}

func (p *push) receive(status string, fn func(json.RawMessage)) *push {
	if p.hasReceived(status) {
		fn(p.received.response)
	}
	p.hooks = append(p.hooks, pushHook{status: status, fn: fn})
	return p
}

// onAbort registers fn to run if the push is destroyed or discarded
// before it resolves. Used to release Go waiters.
func (p *push) onAbort(fn func(error)) { p.aborts = append(p.aborts, fn) }

func (p *push) reset() {
	p.cancelRefEvent()
	p.ref = ""
	p.received = nil
}

func (p *push) destroy() {
	p.cancelRefEvent()
	p.cancelTimeout()
	p.abort(ErrChannelClosed)
}

func (p *push) abort(err error) {
	aborts := p.aborts
	p.aborts = nil
	for _, fn := range aborts {
		fn(err)
	}
}

func (p *push) matchReceive(r *pushReply) {
	hooks := append([]pushHook(nil), p.hooks...)
	for _, h := range hooks {
		if h.status == r.status {
			h.fn(r.response)
		}
	}
}

func (p *push) cancelRefEvent() {
	if p.refEvent == "" {
		return
	}
	if p.ch.replies[p.refEvent] == p {
		delete(p.ch.replies, p.refEvent)
	}
	p.refEvent = ""
}

func (p *push) cancelTimeout() {
	p.timer.stop()
	p.timer = nil
}

func (p *push) startTimeout() {
	if p.timer != nil {
		p.cancelTimeout()
	}
	p.cancelRefEvent()
	p.ref = p.ch.client.makeRef()
	p.refEvent = p.ref
	p.ch.replies[p.refEvent] = p
	p.timer = p.ch.client.after(p.timeout, func() {
		p.timer = nil
		p.trigger("timeout", json.RawMessage("{}"))
	})
}

// handleReply is the refEvent binding: it resolves the push.
func (p *push) handleReply(r *pushReply) {
	p.cancelRefEvent()
	p.cancelTimeout()
	p.received = r
	p.aborts = nil
	p.matchReceive(r)
}

func (p *push) hasReceived(status string) bool {
	return p.received != nil && p.received.status == status
}

// trigger resolves the push locally (phoenix Push.trigger). It is a no-op
// when the push is not waiting for a reply.
func (p *push) trigger(status string, response json.RawMessage) {
	if p.refEvent == "" || p.ch.replies[p.refEvent] != p {
		return
	}
	p.handleReply(&pushReply{status: status, response: response})
}

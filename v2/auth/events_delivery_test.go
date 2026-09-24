package auth

import (
	"sync"
	"sync/atomic"
	"testing"
)

// Regression test: an event enqueued while another goroutine is finishing
// delivery must still be delivered (no lost wakeup).
func TestEventsNeverStranded(t *testing.T) {
	c, err := New(Config{URL: "https://x.supabase.co/auth/v1", APIKey: "k"})
	if err != nil {
		t.Fatal(err)
	}
	var got atomic.Int64
	c.OnAuthStateChange(func(AuthChangeEvent, *Session) { got.Add(1) })
	const goroutines, per = 16, 500
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < per; i++ {
				c.enqueueEvent(EventUserUpdated, nil)
				c.deliverEvents()
			}
		}()
	}
	wg.Wait()
	if n := got.Load(); n != goroutines*per {
		t.Fatalf("delivered %d events, want %d (events stranded in queue)", n, goroutines*per)
	}
}

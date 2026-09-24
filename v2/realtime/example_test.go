package realtime_test

import (
	"context"
	"log"
	"os"

	"github.com/lengzuo/supa/v2/realtime"
)

// A standalone Realtime client.
func ExampleNew() {
	ctx := context.Background()

	client, err := realtime.New(realtime.Config{
		URL:    "wss://your-project-ref.supabase.co/realtime/v1",
		APIKey: os.Getenv("SUPABASE_PUBLISHABLE_KEY"),
	})
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = client.Disconnect(ctx) }()

	ch, err := client.Channel("room-1", realtime.ChannelOptions{})
	if err != nil {
		log.Fatal(err)
	}
	if err := ch.OnBroadcast("*", func(m realtime.BroadcastMessage) {
		log.Printf("%s: %s", m.Event, m.Payload)
	}); err != nil {
		log.Fatal(err)
	}
	if err := ch.Subscribe(ctx); err != nil {
		log.Fatal(err)
	}
}

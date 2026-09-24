package storage_test

import (
	"context"
	"errors"
	"log"
	"os"

	"github.com/lengzuo/supa/v2/storage"
)

func ExampleIsErrorCode() {
	ctx := context.Background()
	client, err := storage.New(storage.Config{
		URL:    "https://your-project-ref.supabase.co/storage/v1",
		APIKey: os.Getenv("SUPABASE_PUBLISHABLE_KEY"),
	})
	if err != nil {
		log.Fatal(err)
	}

	_, err = client.From("avatars").Download(ctx, "missing.png", nil)
	var stErr *storage.Error
	switch {
	case storage.IsErrorCode(err, storage.CodeNoSuchKey):
		log.Print("no such object")
	case storage.IsErrorCode(err, storage.CodeAccessDenied):
		log.Print("denied by a storage RLS policy")
	case errors.As(err, &stErr):
		log.Printf("storage error %d %s: %s", stErr.Status, stErr.Code, stErr.Message)
	}
}

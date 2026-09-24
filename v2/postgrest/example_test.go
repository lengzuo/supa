package postgrest_test

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/lengzuo/supa/v2/postgrest"
)

type Todo struct {
	ID    int64  `json:"id"`
	Title string `json:"title"`
	Done  bool   `json:"done"`
}

// A standalone PostgREST client (it also works with a plain PostgREST server).
func ExampleNew() {
	ctx := context.Background()

	db, err := postgrest.New(postgrest.Config{
		URL:     "https://your-project-ref.supabase.co/rest/v1",
		APIKey:  os.Getenv("SUPABASE_PUBLISHABLE_KEY"),
		Timeout: 10 * time.Second,
	})
	if err != nil {
		log.Fatal(err)
	}

	todos, _, err := postgrest.ExecuteTo[[]Todo](ctx, db.From("todos").Select("*").Eq("done", false))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(len(todos))
}

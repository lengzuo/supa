package functions_test

import (
	"context"
	"errors"
	"log"
	"os"

	"github.com/lengzuo/supa/v2/functions"
)

func ExampleHTTPError() {
	ctx := context.Background()
	client, err := functions.New(functions.Config{
		URL:    "https://your-project-ref.supabase.co/functions/v1",
		APIKey: os.Getenv("SUPABASE_PUBLISHABLE_KEY"),
	})
	if err != nil {
		log.Fatal(err)
	}

	_, err = functions.InvokeJSON[map[string]any](ctx, client, "hello", nil)
	var (
		httpErr  *functions.HTTPError
		relayErr *functions.RelayError
		fetchErr *functions.FetchError
	)
	switch {
	case errors.As(err, &httpErr): // the function returned a non-2xx status
		var body struct {
			Error string `json:"error"`
		}
		if httpErr.DecodeJSON(&body) == nil {
			log.Printf("function failed with %d: %s", httpErr.StatusCode, body.Error)
		}
	case errors.As(err, &relayErr): // Supabase could not invoke the function
		log.Printf("relay error %d", relayErr.StatusCode)
	case errors.As(err, &fetchErr): // network failure, timeout or cancellation
		log.Print("request failed: ", fetchErr.Err)
	}
}

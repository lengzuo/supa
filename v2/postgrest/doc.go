// Package postgrest is a client for PostgREST, the REST API Supabase
// generates for a Postgres database. It mirrors postgrest-js.
//
// Queries are built from immutable values and run with Execute,
// ExecuteInto or the generic ExecuteTo:
//
//	db, err := postgrest.New(postgrest.Config{
//		URL:    "https://<ref>.supabase.co/rest/v1",
//		APIKey: key,
//	})
//	...
//	var todos []Todo
//	resp, err := db.From("todos").
//		Select("id, title, owner:users(name)", postgrest.SelectOptions{Count: postgrest.CountExact}).
//		Eq("done", false).
//		Order("created_at", postgrest.OrderOptions{Descending: true}).
//		Limit(20).
//		ExecuteInto(ctx, &todos)
//	// resp.Count holds the total number of matching rows.
//
// # Errors
//
// Every failure after a query is built is an *Error carrying the
// PostgREST/Postgres Code, Message, Details, Hint and HTTP Status. Network
// failures have Status 0 and unwrap to the underlying error, so
// errors.Is(err, context.DeadlineExceeded) works. Invalid builder input
// (for example a value that cannot be JSON-encoded) is reported by Execute
// as a plain error before any request is sent.
//
// # Concurrency
//
// A *Client and every builder value are safe for concurrent use. Builder
// methods never modify their receiver, so a partially built query can be
// shared and extended from several goroutines.
//
// # Retries and timeouts
//
// By default GET and HEAD requests are retried up to three times on
// network errors and HTTP 503/520 responses, like postgrest-js. See
// RetryPolicy and FilterBuilder.Retry. Config.Timeout bounds each attempt;
// cancel ctx to abort a query.
package postgrest

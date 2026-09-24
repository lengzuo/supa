package auth_test

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/lengzuo/supa/v2/auth"
)

// A standalone Auth client, e.g. for a service that only verifies JWTs.
func ExampleNew() {
	ctx := context.Background()

	client, err := auth.New(auth.Config{
		URL:    "https://your-project-ref.supabase.co/auth/v1",
		APIKey: os.Getenv("SUPABASE_PUBLISHABLE_KEY"),
	})
	if err != nil {
		log.Fatal(err)
	}

	// GetClaims verifies asymmetric JWTs locally against the project's JWKS
	// (falling back to the Auth server for symmetric keys).
	res, err := client.GetClaims(ctx, "user-access-token", nil)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(res.Claims.Subject, res.Claims.Role)
}

func ExampleError() {
	ctx := context.Background()
	client, err := auth.New(auth.Config{
		URL:    "https://your-project-ref.supabase.co/auth/v1",
		APIKey: os.Getenv("SUPABASE_PUBLISHABLE_KEY"),
	})
	if err != nil {
		log.Fatal(err)
	}

	_, err = client.SignInWithPassword(ctx, auth.SignInWithPasswordParams{Email: "ada@example.com", Password: "wrong"})
	var authErr *auth.Error
	if errors.As(err, &authErr) {
		switch authErr.Code {
		case auth.ErrorCodeInvalidCredentials:
			log.Print("wrong email or password")
		case auth.ErrorCodeEmailNotConfirmed:
			log.Print("confirm your email first")
		case auth.ErrorCodeOverRequestRateLimit:
			log.Print("slow down")
		default:
			log.Printf("auth error %d %s: %s (retryable: %t)",
				authErr.StatusCode, authErr.Code, authErr.Message, authErr.Retryable)
		}
	}
	// Sentinel errors match by code.
	if errors.Is(err, auth.ErrSessionMissing) {
		log.Print("not signed in")
	}
}

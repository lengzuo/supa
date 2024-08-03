# supa-go 

`supa-go` is a Golang library that facilitates Supabase API interactions for Golang developers. Supabase is an open-source alternative to Firebase, providing a scalable and secure backend for your applications.

## Installation
```console
go get github.com/lengzuo/supa
```

## Use
```go
import "github.com/lengzuo/supa"
```

This gives you access to the `go-supa` package.

### Initialise client
```go
conf := supabase.Config{
    // Your Supabase API key. 
    ApiKey:     os.Getenv("api_key"), 
    // Your Supabase project reference.
    ProjectRef: os.Getenv("project_ref"),
    // Set Debug to `false` if you don't want to print log
    Debug:      true,
}
supaClient, err := supabase.New(conf)
if err != nil {
    fmt.Printf("failed in initialise client with err: %s", err)
    return
}
// Start using `supaClient` in your go project 
```

### Initialise with your own http client and header
```go
func myHttpClient() *http.Client {
    return http.DefaultClient
}

func newCustomClient() {
    postgresHeader := map[string]string{
        "Accept-Profile":  "public",
        "Content-Profile": "public",
        "X-Client-Info":   "v0.1.1",
    }
    header := map[string]string{
        "CustomHeader": "myCustomHeader",
    }
    conf := supabase.Config{
        // Your Supabase API key. 
        ApiKey:     os.Getenv("api_key"),
        // Your Supabase project reference.
        ProjectRef: os.Getenv("project_ref"),
        // Set Debug to `false` if you don't want to print log
        Debug:      true,
        // Use this options to override /auth with your http client and your header 
	    AuthOptions: []supabase.AuthOption{
            supabase.WithAuthClient(myHttpClient(), header),
        },
        // Use this options to override postgres with your own http client and your header 
        PostgresOptions: []supabase.PostgresOption{
            supabase.WithPostgresClient(myHttpClient(), postgresHeader),
        },
    }
    supaClient, err := supabase.New(conf)
    if err != nil {
        fmt.Printf("failed in initialise client with err: %s", err)
    }
    // Start using `supaClient` in your go project 
}
```

### Sign up
```go
body := dto.SignUpRequest{
    Email:    "test@test.com",
    Password: "abcd1234",
}
resp, err := supaClient.Auth.SignUp(ctx, body)
```

### Sign up
```go
body := dto.SignUpRequest{
    Email:    "test@test.com",
    Password: "abcd1234",
}
resp, err := supaClient.Auth.SignUp(ctx, body)
```

### Sign in with password
```go
body := dto.SignInRequest{
    Email:    "test@test.com",
    Password: "abcd1234",
}
resp, err := supaClient.Auth.SignInWithPassword(ctx, body)
```

### Sign in with OTP
```go
signInBody := dto.SignInRequest{
    Email:      "test@test.com",
    CreateUser: true,
}
err := supaClient.Auth.SignInWithOTP(ctx, signInBody)

// After that, you can verify user OTP with below function
verifyBody := dto.VerifyRequest{
    Email: "test@test.com",
    Token: "12345",
    Type:  enum.MagicLink.String(),
}
auth, err := supaClient.Auth.Verify(ctx, verifyBody)
if err != nil {
    log.Error("failed in calling Verify")
    return
}
bytes, err := json.Marshal(auth)
log.Debug("sign in with verify results: %s", bytes)
```

### Get login user 
```go
token := "eyxxxxxxxx.xxxx...."
user, err := supaClient.Auth.User(ctx, token)
```

### Select more than 1 rows 
```go
ctx := context.Background()
var u []dto.YourTable
query := supaClient.DB.From("your_table").Select("*").Eq("id", "1acaxxxf-xx0d-4xxb-xx48-xxxxx")
err := query.ExecuteWithContext(ctx, &u)
bytes, err := json.Marshal(u)
log.Debug("query your table result: %s", bytes)
```

### Select single row 
```go
ctx := context.Background()
var u dto.YourTable
query := supaClient.DB.From("your_table").Select("*").Eq("id", "1acaxxxf-xx0d-4xxb-xx48-xxxxx").Single()
err := query.ExecuteWithContext(ctx, &u)
bytes, err := json.Marshal(u)
log.Debug("query your table result: %s", bytes)
```

### Insert with return result 
```go
ctx := context.Background()
u := T{
    Name: "test33",
}
query := supaClient.DB.From("test").Insert(u)
r := new(T)
err := query.ExecuteWithContext(ctx, &r)
bytes, err := json.Marshal(u)
log.Debug("query your table result: %s", bytes)
```

### Insert without returning result 
```go
ctx := context.Background()
u := T{
    Name: "test33",
}
query := supaClient.DB.From("test").Insert(u)
err := query.ExecuteWithContext(ctx, nil)
```

### Passing auth token in your query
```go
ctx := context.Background()
var u []YourStruct
query := supaClient.DB.From("user_plans", supabase.AuthToken("mytoken")).Select("*")
err := query.ExecuteWithContext(ctx, &u)
log.Debug("query output: %#v", u)
```

### Delete row [No result return]
```go
ctx := context.Background()
query := supaClient.DB.From("test").Delete().Eq("id", "X")
err := query.ExecuteWithContext(ctx, nil)
log.Debug("delete successful, no result")
```

### RPC
```go
ctx := context.Background()
req := dto.YourRPCStruct{UserID: "xxxx"}
rpcBuilder := supaClient.DB.RPC("your_rpc_method", req)
// You can define any type based on your rpc. My rpc method will return an `int` for my case.
var results int
err := rpcBuilder.ExecuteWithContext(ctx, &results)
log.Debug("rpc result: %s", bytes)
```

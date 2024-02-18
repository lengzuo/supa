package config

type Supabase struct {
	ApiKey     string
	JWTSecret  string
	ProjectRef string
	Bucket     string
	Debug      bool
}

type Config struct {
	Supabase
}

package config

var (
	Version = "0.0.1-dev0"
)

const (
	Name    = "go.micro.auth"
	PkgPath = "jochum.dev/jo-micro/auth2"
)

const (
	EnvDev  = "dev"
	EnvProd = "prod"
)

type Config struct {
	Auth AuthConfig
}

type ServerConfig struct {
	Env       string
	RouterURI string
}

type TokenKeys struct {
	PrivKey string
	PubKey  string
}

type AuthConfig struct {
	Server ServerConfig

	RefreshTokenExpiry int
	AccessTokenExpiry  int
	AccessToken        TokenKeys
	RefreshToken       TokenKeys
}

func GetConfig() *Config {
	return &_cfg
}

func GetServerConfig() ServerConfig {
	return _cfg.Auth.Server
}

func GetAuthConfig() AuthConfig {
	return _cfg.Auth
}

// internal instance of Config with defaults
var _cfg = Config{
	Auth: AuthConfig{
		Server: ServerConfig{
			Env:       EnvProd,
			RouterURI: "auth",
		},

		RefreshTokenExpiry: 86400 * 14, // 14 days
		AccessTokenExpiry:  900,        // 15 minutes
		AccessToken: TokenKeys{
			PrivKey: "",
			PubKey:  "",
		},
		RefreshToken: TokenKeys{
			PrivKey: "",
			PubKey:  "",
		},
	},
}

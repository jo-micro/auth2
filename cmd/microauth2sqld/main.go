package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/urfave/cli/v2"
	"go-micro.dev/v4"
	"go-micro.dev/v4/logger"

	"jochum.dev/jo-micro/auth2"
	"jochum.dev/jo-micro/auth2/cmd/microauth2sqld/config"
	"jochum.dev/jo-micro/auth2/cmd/microauth2sqld/handler"
	"jochum.dev/jo-micro/auth2/internal/proto/authpb"
	"jochum.dev/jo-micro/buncomponent"
	"jochum.dev/jo-micro/components"
	"jochum.dev/jo-micro/logruscomponent"
	"jochum.dev/jo-micro/router"

	"jochum.dev/jo-micro/auth2/plugins/client/jwt"
)

var (
	ErrorNoKeys = errors.New("config AUTH2_JWT_*_KEY or AUTH2_JWT_REFRESH_*_KEY not given")
)

func generateEd25519PEMKeyPair() (string, string, error) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}

	privPKCS8, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return "", "", err
	}

	privPem := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privPKCS8,
	})

	pubPKCS8, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return "", "", err
	}

	pubPem := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubPKCS8,
	})

	return base64.StdEncoding.EncodeToString(pubPem), base64.StdEncoding.EncodeToString(privPem), nil
}

func generateRSAPEMKeyPair(bits int) (string, string, error) {
	privKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return "", "", err
	}

	privPKCS8, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return "", "", err
	}

	privPem := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privPKCS8,
	})

	pubPKCS8, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return "", "", err
	}

	pubPem := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubPKCS8,
	})

	return base64.StdEncoding.EncodeToString(pubPem), base64.StdEncoding.EncodeToString(privPem), nil
}

func main() {
	service := micro.NewService()
	cReg := components.New(service, "auth2", logruscomponent.New(), auth2.ClientAuthComponent(), buncomponent.New(), router.New())

	auth2ClientReg := auth2.ClientAuthMustReg(cReg)
	auth2ClientReg.Register(jwt.New())
	auth2ClientReg.ForcePlugin("jwt")

	flags := []cli.Flag{
		// Generate
		&cli.BoolFlag{
			Name:  "auth2_generate_keys",
			Usage: "Generate keys for the config and/or the environment",
			Value: false,
		},
		&cli.StringFlag{
			Name:  "auth2_generate_format",
			Usage: "Format for \"auth2_generate_keys\", \"RSA4096\", \"RSA2048\" or \"Ed25519\"",
			Value: "Ed25519",
		},

		// General
		&cli.StringFlag{
			Name:    "auth2_sqld_router_basepath",
			Usage:   "Router basepath",
			EnvVars: []string{"AUTH2_SQLD_ROUTER_BASEPATH"},
			Value:   "auth",
		},

		// Keys
		// given by they ClientAuth
		&cli.StringFlag{
			Name:    "auth2_jwt_pub_key",
			Usage:   "Public access key PEM base64 encoded",
			EnvVars: []string{"AUTH2_JWT_PUB_KEY"},
		},
		&cli.StringFlag{
			Name:    "auth2_jwt_priv_key",
			Usage:   "Private access key PEM base64 encoded",
			EnvVars: []string{"AUTH2_JWT_PRIV_KEY"},
		},
		&cli.StringFlag{
			Name:    "auth2_jwt_refresh_pub_key",
			Usage:   "Public refresh key PEM base64 encoded",
			EnvVars: []string{"AUTH2_JWT_REFRESH_PUB_KEY"},
		},
		&cli.StringFlag{
			Name:    "auth2_jwt_refresh_priv_key",
			Usage:   "Private refresh key PEM base64 encoded",
			EnvVars: []string{"AUTH2_JWT_REFRESH_PRIV_KEY"},
		},

		// Token
		&cli.Int64Flag{
			Name:    "auth2_jwt_refresh_expiry",
			Usage:   "Expire the refreshtoken after x seconds, default is one day",
			EnvVars: []string{"AUTH2_JWT_REFRESH_EXPIRY"},
			Value:   86400,
		},
		&cli.Int64Flag{
			Name:    "auth2_jwt_access_expiry",
			Usage:   "Expire the accesstoken after x seconds, default is 15 minutes",
			EnvVars: []string{"AUTH2_JWT_ACCESS_EXPIRY"},
			Value:   900,
		},
		&cli.StringSliceFlag{
			Name:    "auth2_jwt_audience",
			Usage:   "Add and expect this JWT audience",
			EnvVars: []string{"AUTH2_JWT_AUDIENCES"},
		},
	}

	authHandler := handler.NewHandler()

	opts := []micro.Option{
		micro.Name(config.Name),
		micro.Version(config.Version),
		micro.Flags(components.FilterDuplicateFlags(cReg.AppendFlags(flags))...),
		micro.WrapHandler(auth2ClientReg.WrapHandler()),
		micro.Action(func(c *cli.Context) error {
			if c.Bool("auth2_generate_keys") {
				var (
					aPubKey  string
					aPrivKey string
					rPubKey  string
					rPrivKey string
					err      error
				)

				// Just generate keys and print them to the commandline
				switch c.String("auth2_generate_format") {
				case "Ed25519":
					aPubKey, aPrivKey, err = generateEd25519PEMKeyPair()
					if err != nil {
						logger.Fatal(err)
						return err
					}

					rPubKey, rPrivKey, err = generateEd25519PEMKeyPair()
					if err != nil {
						logger.Fatal(err)
						return err
					}
				case "RSA4096":
					aPubKey, aPrivKey, err = generateRSAPEMKeyPair(4096)
					if err != nil {
						logger.Fatal(err)
						return err
					}

					rPubKey, rPrivKey, err = generateRSAPEMKeyPair(4096)
					if err != nil {
						logger.Fatal(err)
						return err
					}
				case "RSA2048":
					aPubKey, aPrivKey, err = generateRSAPEMKeyPair(2048)
					if err != nil {
						logger.Fatal(err)
						return err
					}

					rPubKey, rPrivKey, err = generateRSAPEMKeyPair(2048)
					if err != nil {
						logger.Fatal(err)
						return err
					}
				default:
					logger.Fatalf("unknown key format: %s", c.String("auth2_generate_format"))
					return err
				}

				absPath, err := exec.LookPath(os.Args[0])
				if err != nil {
					// Don't fail here
					absPath = os.Args[0]
				}

				fmt.Printf("# go.micro.auth %s JWT keys in PEM - generated using '%s %s'\n", c.String("auth2_generate_format"), absPath, strings.Join(os.Args[1:len(os.Args)], " "))
				fmt.Printf("AUTH2_JWT_PRIV_KEY=\"%s\"\n", aPrivKey)
				fmt.Printf("AUTH2_JWT_PUB_KEY=\"%s\"\n", aPubKey)
				fmt.Printf("AUTH2_JWT_REFRESH_PRIV_KEY=\"%s\"\n", rPrivKey)
				fmt.Printf("AUTH2_JWT_REFRESH_PUB_KEY=\"%s\"\n", rPubKey)

				os.Exit(0)
			}

			// Start the components
			if err := cReg.Init(c); err != nil {
				logger.Fatal(err)
				return err
			}

			logger := logruscomponent.MustReg(cReg).Logger()

			// Check if we got keys
			if c.String("auth2_jwt_pub_key") == "" || c.String("auth2_jwt_priv_key") == "" || c.String("auth2_jwt_refresh_pub_key") == "" || c.String("auth2_jwt_refresh_priv_key") == "" {
				logger.Fatal(ErrorNoKeys)
				return ErrorNoKeys
			}

			// Check the other handler cli arguments
			if c.Int64("auth2_jwt_access_expiry") < 1 {
				err := errors.New("AUTH2_JWT_ACCESS_EXPIRY must be great than 0")
				logger.Fatal(err)
				return err
			}
			if c.Int64("auth2_jwt_refresh_expiry") < 1 {
				err := errors.New("AUTH2_JWT_REFRESH_EXPIRY must be great than 0")
				logger.Fatal(err)
				return err
			}
			if c.StringSlice("auth2_jwt_audience") == nil {
				err := errors.New("AUTH2_JWT_AUDIENCES must be given")
				logger.Fatal(err)
				return err
			}

			if err := authHandler.Init(cReg, handler.InitConfig{
				Audiences:           c.StringSlice("auth2_jwt_audience"),
				RefreshTokenExpiry:  c.Int64("auth2_jwt_refresh_expiry"),
				AccessTokenExpiry:   c.Int64("auth2_jwt_access_expiry"),
				AccessTokenPubKey:   c.String("auth2_jwt_pub_key"),
				AccessTokenPrivKey:  c.String("auth2_jwt_priv_key"),
				RefreshTokenPubKey:  c.String("auth2_jwt_refresh_pub_key"),
				RefreshTokenPrivKey: c.String("auth2_jwt_refresh_priv_key"),
			}); err != nil {
				logger.Fatal(err)
				return err
			}
			authpb.RegisterAuthServiceHandler(service.Server(), authHandler)

			return nil
		}),
	}

	service.Init(opts...)

	// Run server
	if err := service.Run(); err != nil {
		logruscomponent.MustReg(cReg).Logger().Fatal(err)
		return
	}

	// Stop the auth Plugin
	if err := cReg.Stop(); err != nil {
		logger.Fatal(err)
		return
	}
}

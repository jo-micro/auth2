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
	"jochum.dev/jo-micro/auth2/internal/ibun"
	"jochum.dev/jo-micro/auth2/internal/ilogger"
	"jochum.dev/jo-micro/auth2/internal/proto/authpb"
	"jochum.dev/jo-micro/router"

	_ "jochum.dev/jo-micro/auth2/plugins/client/jwt"
	"jochum.dev/jo-micro/auth2/plugins/verifier/endpointroles"
)

var (
	ErrorNoKeys = errors.New("config MICRO_AUTH2_JWT_*_KEY or MICRO_AUTH2_JWT_REFRESH_*_KEY not given")
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
	srv := micro.NewService()

	auth2ClientReg := auth2.ClientAuthRegistry()
	auth2ClientReg.ForcePlugin("jwt")

	flags := ibun.AppendFlags(ilogger.AppendFlags(auth2ClientReg.MergeFlags([]cli.Flag{
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
			EnvVars: []string{"MICRO_AUTH2_SQLD_ROUTER_BASEPATH"},
			Value:   "auth",
		},

		// Keys
		// given by they ClientAuth
		&cli.StringFlag{
			Name:    "auth2_jwt_pub_key",
			Usage:   "Public access key PEM base64 encoded",
			EnvVars: []string{"MICRO_AUTH2_JWT_PUB_KEY"},
		},
		&cli.StringFlag{
			Name:    "auth2_jwt_priv_key",
			Usage:   "Private access key PEM base64 encoded",
			EnvVars: []string{"MICRO_AUTH2_JWT_PRIV_KEY"},
		},
		&cli.StringFlag{
			Name:    "auth2_jwt_refresh_pub_key",
			Usage:   "Public refresh key PEM base64 encoded",
			EnvVars: []string{"MICRO_AUTH2_JWT_REFRESH_PUB_KEY"},
		},
		&cli.StringFlag{
			Name:    "auth2_jwt_refresh_priv_key",
			Usage:   "Private refresh key PEM base64 encoded",
			EnvVars: []string{"MICRO_AUTH2_JWT_REFRESH_PRIV_KEY"},
		},

		// Token
		&cli.Int64Flag{
			Name:    "auth2_jwt_refresh_expiry",
			Usage:   "Expire the refreshtoken after x seconds, default is one day",
			EnvVars: []string{"MICRO_AUTH2_JWT_REFRESH_EXPIRY"},
			Value:   86400,
		},
		&cli.Int64Flag{
			Name:    "auth2_jwt_access_expiry",
			Usage:   "Expire the accesstoken after x seconds, default is 15 minutes",
			EnvVars: []string{"MICRO_AUTH2_JWT_ACCESS_EXPIRY"},
			Value:   900,
		},
		&cli.StringSliceFlag{
			Name:    "auth2_jwt_audience",
			Usage:   "Add and expect this JWT audience",
			EnvVars: []string{"MICRO_AUTH2_JWT_AUDIENCES"},
		},
	})))

	authHandler := handler.NewHandler()

	opts := []micro.Option{
		micro.Name(config.Name),
		micro.Version(config.Version),
		micro.Flags(flags...),
		micro.WrapHandler(auth2ClientReg.Wrapper()),
		micro.Action(func(c *cli.Context) error {
			// Start the logger
			if err := ilogger.Start(c); err != nil {
				logger.Fatal(err)
				return err
			}

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
						ilogger.Logrus().Fatal(err)
					}

					rPubKey, rPrivKey, err = generateEd25519PEMKeyPair()
					if err != nil {
						ilogger.Logrus().Fatal(err)
					}
				case "RSA4096":
					aPubKey, aPrivKey, err = generateRSAPEMKeyPair(4096)
					if err != nil {
						ilogger.Logrus().Fatal(err)
					}

					rPubKey, rPrivKey, err = generateRSAPEMKeyPair(4096)
					if err != nil {
						ilogger.Logrus().Fatal(err)
					}
				case "RSA2048":
					aPubKey, aPrivKey, err = generateRSAPEMKeyPair(2048)
					if err != nil {
						ilogger.Logrus().Fatal(err)
					}

					rPubKey, rPrivKey, err = generateRSAPEMKeyPair(2048)
					if err != nil {
						ilogger.Logrus().Fatal(err)
					}
				default:
					ilogger.Logrus().Fatalf("unknown key format: %s", c.String("auth2_generate_format"))
				}

				absPath, err := exec.LookPath(os.Args[0])
				if err != nil {
					// Don't fail here
					absPath = os.Args[0]
				}

				fmt.Printf("# go.micro.auth %s JWT keys in PEM - generated using '%s %s'\n", c.String("auth2_generate_format"), absPath, strings.Join(os.Args[1:len(os.Args)], " "))
				fmt.Printf("MICRO_AUTH2_JWT_PRIV_KEY=\"%s\"\n", aPrivKey)
				fmt.Printf("MICRO_AUTH2_JWT_PUB_KEY=\"%s\"\n", aPubKey)
				fmt.Printf("MICRO_AUTH2_JWT_REFRESH_PRIV_KEY=\"%s\"\n", rPrivKey)
				fmt.Printf("MICRO_AUTH2_JWT_REFRESH_PUB_KEY=\"%s\"\n", rPubKey)

				os.Exit(0)
			}

			if err := auth2ClientReg.Init(c, srv); err != nil {
				ilogger.Logrus().Fatal(err)
			}

			authVerifier := endpointroles.NewVerifier(
				endpointroles.WithLogrus(ilogger.Logrus()),
			)
			authVerifier.AddRules(
				endpointroles.RouterRule,
				endpointroles.NewRule(
					endpointroles.Endpoint(authpb.AuthService.Delete),
					endpointroles.RolesAllow(auth2.RolesServiceAndAdmin),
				),
				endpointroles.NewRule(
					endpointroles.Endpoint(authpb.AuthService.Detail),
					endpointroles.RolesAllow(auth2.RolesServiceAndUsersAndAdmin),
				),
				endpointroles.NewRule(
					endpointroles.Endpoint(authpb.AuthService.Inspect),
					endpointroles.RolesAllow(auth2.RolesServiceAndUsersAndAdmin),
				),
				endpointroles.NewRule(
					endpointroles.Endpoint(authpb.AuthService.List),
					endpointroles.RolesAllow(auth2.RolesServiceAndAdmin),
				),
				endpointroles.NewRule(
					endpointroles.Endpoint(authpb.AuthService.Login),
					endpointroles.RolesAllow(auth2.RolesAllAndAnon),
				),
				endpointroles.NewRule(
					endpointroles.Endpoint(authpb.AuthService.Refresh),
					endpointroles.RolesAllow(auth2.RolesAllAndAnon),
				),
				endpointroles.NewRule(
					endpointroles.Endpoint(authpb.AuthService.Register),
					endpointroles.RolesAllow(auth2.RolesAllAndAnon),
				),
				endpointroles.NewRule(
					endpointroles.Endpoint(authpb.AuthService.UpdateRoles),
					endpointroles.RolesAllow(auth2.RolesAdmin),
				),
			)
			auth2ClientReg.Plugin().SetVerifier(authVerifier)

			// Connect to the database
			if err := ibun.Start(c); err != nil {
				ilogger.Logrus().Fatal(err)
			}

			// Check if we got keys
			if c.String("auth2_jwt_pub_key") == "" || c.String("auth2_jwt_priv_key") == "" || c.String("auth2_jwt_refresh_pub_key") == "" || c.String("auth2_jwt_refresh_priv_key") == "" {
				ilogger.Logrus().Fatal(ErrorNoKeys)
			}

			// Check the other handler cli arguments
			if c.Int64("auth2_jwt_access_expiry") < 1 {
				ilogger.Logrus().Fatal(errors.New("MICRO_AUTH2_JWT_ACCESS_EXPIRY must be great than 0"))
			}
			if c.Int64("auth2_jwt_refresh_expiry") < 1 {
				ilogger.Logrus().Fatal(errors.New("MICRO_AUTH2_JWT_REFRESH_EXPIRY must be great than 0"))
			}
			if c.StringSlice("auth2_jwt_audience") == nil {
				ilogger.Logrus().Fatal(errors.New("MICRO_AUTH2_JWT_AUDIENCES must be given"))
			}

			if err := authHandler.Init(handler.InitConfig{
				Audiences:           c.StringSlice("auth2_jwt_audience"),
				RefreshTokenExpiry:  c.Int64("auth2_jwt_refresh_expiry"),
				AccessTokenExpiry:   c.Int64("auth2_jwt_access_expiry"),
				AccessTokenPubKey:   c.String("auth2_jwt_pub_key"),
				AccessTokenPrivKey:  c.String("auth2_jwt_priv_key"),
				RefreshTokenPubKey:  c.String("auth2_jwt_refresh_pub_key"),
				RefreshTokenPrivKey: c.String("auth2_jwt_refresh_priv_key"),
			}); err != nil {
				ilogger.Logrus().Fatal(err)
			}
			authpb.RegisterAuthServiceHandler(srv.Server(), authHandler)

			// Register with https://jochum.dev/jo-micro/router
			r := router.NewHandler(
				c.String("auth2_sqld_router_basepath"),
				router.NewRoute(
					router.Method(router.MethodGet),
					router.Path("/"),
					router.Endpoint(authpb.AuthService.List),
					router.Params("limit", "offset"),
					router.AuthRequired(),
				),
				router.NewRoute(
					router.Method(router.MethodPost),
					router.Path("/login"),
					router.Endpoint(authpb.AuthService.Login),
				),
				router.NewRoute(
					router.Method(router.MethodPost),
					router.Path("/register"),
					router.Endpoint(authpb.AuthService.Register),
				),
				router.NewRoute(
					router.Method(router.MethodPost),
					router.Path("/refresh"),
					router.Endpoint(authpb.AuthService.Refresh),
				),
				router.NewRoute(
					router.Method(router.MethodDelete),
					router.Path("/:userId"),
					router.Endpoint(authpb.AuthService.Delete),
					router.Params("userId"),
					router.AuthRequired(),
				),
				router.NewRoute(
					router.Method(router.MethodGet),
					router.Path("/:userId"),
					router.Endpoint(authpb.AuthService.Detail),
					router.Params("userId"),
					router.AuthRequired(),
				),
				router.NewRoute(
					router.Method(router.MethodPut),
					router.Path("/:userId/roles"),
					router.Endpoint(authpb.AuthService.UpdateRoles),
					router.Params("userId"),
					router.AuthRequired(),
				),
			)
			r.RegisterWithServer(srv.Server())
			return nil
		}),
	}

	srv.Init(opts...)

	// Run server
	if err := srv.Run(); err != nil {
		ilogger.Logrus().Fatal(err)
	}

	// Disconnect from the database
	if err := ibun.Stop(); err != nil {
		ilogger.Logrus().Fatal(err)
	}

	// Stop the auth Plugin
	if err := auth2ClientReg.Stop(); err != nil {
		ilogger.Logrus().Fatal(err)
	}

	// Stop the logger
	if err := ilogger.Stop(); err != nil {
		logger.Fatal(err)
	}
}

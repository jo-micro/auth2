package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"

	"github.com/urfave/cli/v2"
	"go-micro.dev/v4"
	"go-micro.dev/v4/logger"

	"jochum.dev/jo-micro/auth2/cmd/microauthsqld/config"
	iconfig "jochum.dev/jo-micro/auth2/internal/config"
	iLogger "jochum.dev/jo-micro/auth2/internal/logger"
	"jochum.dev/jo-micro/router"

	"jochum.dev/jo-micro/auth2/internal/bun"
)

var (
	ErrorNoKeys = errors.New("config AUTH_ACCESS_TOKEN_*_KEY or AUTH_REFRESH_TOKEN_*_KEY not given")
)

func main() {
	if err := iconfig.Load(config.GetConfig()); err != nil {
		logger.Fatal(err)
	}

	srv := micro.NewService()

	flags := []cli.Flag{
		&cli.BoolFlag{
			Name:  "generate-keys",
			Usage: "Generate keys for the config and/or the environment",
			Value: false,
		},
	}
	flags = append(flags, bun.Flags()...)
	flags = append(flags, iLogger.Flags()...)

	opts := []micro.Option{
		micro.Name(config.Name),
		micro.Version(config.Version),
		micro.Flags(flags...),
		micro.Action(func(c *cli.Context) error {
			if c.Bool("generate-keys") {
				// Just generate keys and print them to the commandline
				aPubKeyB, aPrivKeyB, err := ed25519.GenerateKey(nil)
				if err != nil {
					log.Fatal(err)
					return err
				}
				rPubKeyB, rPrivKeyB, err := ed25519.GenerateKey(nil)
				if err != nil {
					log.Fatal(err)
					return err
				}

				absPath, err := exec.LookPath(os.Args[0])
				if err != nil {
					// Don't fail here
					absPath = os.Args[0]
				}

				fmt.Printf("# go.micro.auth ed25519 JWT keys - generated using '%s %s'\n", absPath, strings.Join(os.Args[1:len(os.Args)], " "))
				fmt.Printf("AUTH_ACCESSTOKEN_PRIVKEY=\"%s\"\n", base64.StdEncoding.EncodeToString(aPrivKeyB))
				fmt.Printf("AUTH_ACCESSTOKEN_PUBKEY=\"%s\"\n", base64.StdEncoding.EncodeToString(aPubKeyB))
				fmt.Printf("AUTH_REFRESHTOKEN_PRIVKEY=\"%s\"\n", base64.StdEncoding.EncodeToString(rPrivKeyB))
				fmt.Printf("AUTH_REFRESHTOKEN_PUBKEY=\"%s\"\n", base64.StdEncoding.EncodeToString(rPubKeyB))

				os.Exit(0)
			}

			// Start the logger
			if err := iLogger.Start(c); err != nil {
				log.Fatal(err)
				return err
			}

			// Connect to the database
			if err := bun.Start(c); err != nil {
				log.Fatal(err)
				return err
			}

			// Check if we got keys
			authConfig := config.GetAuthConfig()
			if authConfig.AccessToken.PrivKey == "" || authConfig.AccessToken.PubKey == "" || authConfig.RefreshToken.PrivKey == "" || authConfig.RefreshToken.PubKey == "" {
				log.Fatal(ErrorNoKeys)
				return ErrorNoKeys
			}

			// Register with https://jochum.dev/jo-micro/router
			r := router.NewHandler(
				config.GetServerConfig().RouterURI,
				router.NewRoute(
					router.Method(router.MethodGet),
					router.Path("/routes"),
					router.Endpoint("routes"),
				),
			)
			r.RegisterWithServer(srv.Server())

			return nil
		}),
	}

	srv.Init(opts...)

	// Run server
	if err := srv.Run(); err != nil {
		logger.Fatal(err)
	}

	// Disconnect from the database
	if err := bun.Stop(); err != nil {
		logger.Fatal(err)
	}

	// Stop the logger
	if err := iLogger.Stop(); err != nil {
		logger.Fatal(err)
	}
}

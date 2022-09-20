package jwt

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/golang-jwt/jwt/v4"
	"github.com/urfave/cli/v2"
	"go-micro.dev/v4"
	"go-micro.dev/v4/metadata"
	"go-micro.dev/v4/server"
	"jochum.dev/jo-micro/auth2"
	"jochum.dev/jo-micro/auth2/internal/util"
)

type jWTClaims struct {
	*jwt.StandardClaims
	Type   string   `json:"type,omitempty"`
	Roles  []string `json:"roles,omitempty"`
	Scopes []string `json:"scopes,omitempty"`
}

func init() {
	auth.ClientAuthRegistry().Register(newJWTPlugin())
}

func newJWTPlugin() auth.ClientPlugin {
	return new(jwtPlugin)
}

type jwtPlugin struct {
	pubKey any
}

func (p *jwtPlugin) String() string {
	return "jwt"
}

func (p *jwtPlugin) Flags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:    "auth2_jwt_pub_key",
			Usage:   "Public key PEM base64 encoded",
			EnvVars: []string{"MICRO_AUTH2_JWT_PUB_KEY"},
		},
	}
}

func (p *jwtPlugin) Init(cli *cli.Context, service micro.Service) error {
	if len(cli.String("auth2_jwt_pub_key")) < 1 {
		return errors.New("you must provide micro-auth-jwt-pub-key")
	}
	aPub, err := base64.StdEncoding.DecodeString(cli.String("micro-auth-jwt-pub-key"))
	if err != nil {
		return err
	}

	block, _ := pem.Decode(aPub)
	if block == nil {
		return errors.New("failed to parse PEM block containing the key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return err
	}

	p.pubKey = pub

	return nil
}

func (p *jwtPlugin) Stop() error {
	return nil
}

func (p *jwtPlugin) Health(ctx context.Context) (string, error) {
	return "All fine", nil
}

func (p *jwtPlugin) Inspect(ctx context.Context) (*auth.User, error) {
	md, ok := metadata.FromContext(ctx)
	if !ok {
		return nil, errors.New("failed to extract metadata from context")
	}

	authH, ok := md.Get("Authorization")
	if !ok {
		return nil, errors.New("failed to get Authorization header from context")
	}

	aTokenString, _, err := util.ExtractToken(authH)
	if err != nil {
		return nil, err
	}

	claims := jWTClaims{}
	_, err = jwt.ParseWithClaims(aTokenString, &claims, func(token *jwt.Token) (interface{}, error) {
		return p.pubKey, nil
	})
	if err != nil {
		return nil, err
	}

	cMD := map[string]string{
		"Audience":  claims.Audience,
		"ExpiresAt": fmt.Sprintf("%d", claims.ExpiresAt),
		"IssuedAt":  fmt.Sprintf("%d", claims.IssuedAt),
		"NotBefore": fmt.Sprintf("%d", claims.NotBefore),
		"Subject":   claims.Subject,
	}

	return &auth.User{Id: claims.Id, Type: claims.Type, Issuer: claims.Issuer, Metadata: cMD, Scopes: claims.Scopes, Roles: claims.Roles}, nil
}

func (p *jwtPlugin) Wrapper() server.HandlerWrapper {
	return func(h server.HandlerFunc) server.HandlerFunc {
		return func(ctx context.Context, req server.Request, rsp interface{}) error {
			_, err := p.Inspect(ctx)
			if err != nil {
				return err
			}

			return h(ctx, req, rsp)
		}
	}
}

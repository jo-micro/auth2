package jwt

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v4"
	"github.com/urfave/cli/v2"
	"go-micro.dev/v4"
	"go-micro.dev/v4/metadata"
	auth "jochum.dev/jo-micro/auth2"
	"jochum.dev/jo-micro/auth2/shared/sjwt"
	"jochum.dev/jo-micro/auth2/shared/sutil"
)

func init() {
	auth.RouterAuthRegistry().Register(newJWTPlugin())
}

func newJWTPlugin() auth.RouterPlugin {
	return new(jwtPlugin)
}

type jwtPlugin struct {
	pubKey any
}

func (p *jwtPlugin) String() string {
	return "jwt"
}

func (p *jwtPlugin) AppendFlags(flags []cli.Flag) []cli.Flag {
	return sutil.MergeFlag(flags, &cli.StringFlag{
		Name:    "auth2_jwt_pub_key",
		Usage:   "Public key PEM base64 encoded",
		EnvVars: []string{"MICRO_AUTH2_JWT_PUB_KEY"},
	})
}

func (p *jwtPlugin) Init(cli *cli.Context, service micro.Service) error {
	if len(cli.String("auth2_jwt_pub_key")) < 1 {
		return errors.New("you must provide auth2_jwt_pub_key")
	}
	aPub, err := base64.StdEncoding.DecodeString(cli.String("auth2_jwt_pub_key"))
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

func (p *jwtPlugin) Inspect(r *http.Request) (*auth.User, error) {
	if h := r.Header.Get("Authorization"); len(h) > 0 {
		return nil, errors.New("failed to get Authorization header from context")
	}

	aTokenString, _, err := sutil.ExtractToken(r.Header.Get("Authorization"))
	if err != nil {
		return nil, err
	}

	claims := sjwt.JWTClaims{}
	_, err = jwt.ParseWithClaims(aTokenString, &claims, func(token *jwt.Token) (interface{}, error) {
		return p.pubKey, nil
	})
	if err != nil {
		return nil, err
	}

	cMD := map[string]string{
		"Audience":  strings.Join(claims.Audience, ","),
		"ExpiresAt": fmt.Sprintf("%d", claims.ExpiresAt),
		"IssuedAt":  fmt.Sprintf("%d", claims.IssuedAt),
		"NotBefore": fmt.Sprintf("%d", claims.NotBefore),
		"Subject":   claims.Subject,
	}

	return &auth.User{Id: claims.ID, Type: claims.Type, Issuer: claims.Issuer, Metadata: cMD, Scopes: claims.Scopes, Roles: claims.Roles}, nil
}

func (p *jwtPlugin) ForwardContext(r *http.Request, ctx context.Context) (context.Context, error) {
	_, err := p.Inspect(r)
	if err != nil {
		return ctx, err
	}

	md := metadata.Metadata{
		"Authorization": r.Header.Get("Authorization"),
	}

	if v := r.Header.Get("X-Forwarded-For"); len(v) > 0 {
		md["X-Fowarded-For"] = v
	}

	return metadata.MergeContext(ctx, md, true), nil
}

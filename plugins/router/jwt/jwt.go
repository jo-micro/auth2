package jwt

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v4"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
	"go-micro.dev/v4/errors"
	"go-micro.dev/v4/metadata"
	"jochum.dev/jo-micro/auth2"
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
	pubKey  any
	options auth2.InitOptions
}

func (p *jwtPlugin) logrus() *logrus.Logger {
	if p.options.Logrus == nil {
		return logrus.StandardLogger()
	}

	return p.options.Logrus
}

func (p *jwtPlugin) String() string {
	return "jwt"
}

func (p *jwtPlugin) MergeFlags(flags []cli.Flag) []cli.Flag {
	return sutil.MergeFlag(flags, &cli.StringFlag{
		Name:    "auth2_jwt_pub_key",
		Usage:   "Public key PEM base64 encoded",
		EnvVars: []string{"MICRO_AUTH2_JWT_PUB_KEY"},
	})
}

func (p *jwtPlugin) Init(opts ...auth2.InitOption) error {
	options, err := auth2.NewInitOptions(opts...)
	if err != nil {
		return err
	}

	if len(options.CliContext.String("auth2_jwt_pub_key")) < 1 {
		return errors.InternalServerError("auth2/plugins/router/jwt.Init:No auth2_jwt_pub_key", "you must provide auth2_jwt_pub_key")
	}
	aPub, err := base64.StdEncoding.DecodeString(options.CliContext.String("auth2_jwt_pub_key"))
	if err != nil {
		return err
	}

	block, _ := pem.Decode(aPub)
	if block == nil {
		return errors.InternalServerError("auth2/plugins/router/jwt.Init:PEM parsing", "failed to parse PEM block containing the key")
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
	if _, ok := r.Header["Authorization"]; !ok {
		p.logrus().WithField("headers", r.Header).Debug("empty or no Authorization header in request")
		return nil, errors.InternalServerError("auth2/plugins/router/jwt.Inspect", "empty or no Authorization header in request")
	}

	aTokenString, _, err := sutil.ExtractToken(r.Header["Authorization"][0])
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
	u, err := p.Inspect(r)
	if err != nil {
		return ctx, err
	}

	md := metadata.Metadata{
		"Authorization": r.Header.Get("Authorization"),
	}

	if v := r.Header.Get("X-Forwarded-For"); len(v) > 0 {
		md["X-Fowarded-For"] = v
	}

	p.logrus().WithField("username", u.Metadata["Subject"]).Trace("Forwarding user")

	return metadata.MergeContext(ctx, md, true), nil
}

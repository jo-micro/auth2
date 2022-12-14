package jwt

import (
	"context"
	"crypto/ed25519"
	"crypto/rsa"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/urfave/cli/v2"
	"go-micro.dev/v4/metadata"
	"go-micro.dev/v4/server"
	"jochum.dev/jo-micro/auth2"
	"jochum.dev/jo-micro/auth2/shared/sjwt"
	"jochum.dev/jo-micro/auth2/shared/sutil"
	"jochum.dev/jo-micro/components"
)

func New() auth2.ClientPlugin {
	return &jwtPlugin{
		verifiers: []auth2.VerifierPlugin{},
	}
}

type jwtPlugin struct {
	audiences []string
	pubKey    any
	privKey   any
	verifiers []auth2.VerifierPlugin
}

func (p *jwtPlugin) String() string {
	return "jwt"
}

func (p *jwtPlugin) Flags(r *components.Registry) []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:    "auth2_jwt_pub_key",
			Usage:   "Public key PEM base64 encoded for access keys",
			EnvVars: []string{"AUTH2_JWT_PUB_KEY"},
		}, &cli.StringFlag{
			Name:    "auth2_jwt_priv_key",
			Usage:   "Private key PEM base64 encoded for access keys",
			EnvVars: []string{"AUTH2_JWT_PRIV_KEY"},
		}, &cli.StringSliceFlag{
			Name:    "auth2_jwt_audience",
			Usage:   "Add and expect this JWT audience",
			EnvVars: []string{"AUTH2_JWT_AUDIENCES"},
		},
	}
}

func (p *jwtPlugin) Init(r *components.Registry, cli *cli.Context) error {
	if len(cli.String("auth2_jwt_pub_key")) < 1 || len(cli.String("auth2_jwt_priv_key")) < 1 {
		return errors.New("you must provide auth2_jwt_(priv|pub)_key")
	}

	if cli.StringSlice("auth2_jwt_audience") == nil {
		return errors.New("AUTH2_JWT_AUDIENCES must be given")
	}

	pub, priv, err := sjwt.DecodeKeyPair(cli.String("auth2_jwt_pub_key"), cli.String("auth2_jwt_priv_key"))
	if err != nil {
		return err
	}

	p.audiences = cli.StringSlice("auth2_jwt_audience")
	p.pubKey = pub
	p.privKey = priv

	return nil
}

func (p *jwtPlugin) Stop() error {
	return nil
}

func (p *jwtPlugin) Health(ctx context.Context) error {
	return nil
}

func (p *jwtPlugin) AddVerifier(v auth2.VerifierPlugin) {
	p.verifiers = append(p.verifiers, v)
}

func (p *jwtPlugin) ServiceContext(ctx context.Context) (context.Context, error) {
	user := auth2.ServiceUser

	// Create the AccessToken
	accessClaims := sjwt.JWTClaims{
		RegisteredClaims: &jwt.RegisteredClaims{
			Issuer:    user.Issuer,
			Subject:   user.Metadata["Subject"],
			Audience:  p.audiences,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Duration(10) * time.Second)),
			NotBefore: jwt.NewNumericDate(time.Now().Add(-time.Second)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ID:        user.Id,
		},
		Roles: user.Roles,
	}
	if err := accessClaims.Valid(); err != nil {
		return ctx, err
	}

	var accessToken *jwt.Token
	switch p.privKey.(type) {
	case *rsa.PrivateKey:
		accessToken = jwt.NewWithClaims(jwt.SigningMethodRS512, accessClaims)
	case ed25519.PrivateKey:
		accessToken = jwt.NewWithClaims(jwt.SigningMethodEdDSA, accessClaims)
	}
	accessSignedToken, err := accessToken.SignedString(p.privKey)
	if err != nil {
		return ctx, err
	}

	md := metadata.Metadata{
		"Authorization": fmt.Sprintf("Bearer %s", accessSignedToken),
	}

	ctx = metadata.MergeContext(ctx, md, true)
	return ctx, nil
}

func (p *jwtPlugin) Inspect(ctx context.Context) (*auth2.User, error) {
	md, ok := metadata.FromContext(ctx)
	if !ok {
		return nil, errors.New("failed to extract metadata from context")
	}

	authH, ok := md.Get("Authorization")
	if !ok {
		return nil, errors.New("failed to get Authorization header from context")
	}

	aTokenString, _, err := sutil.ExtractToken(authH)
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

	return &auth2.User{Id: claims.ID, Type: claims.Type, Issuer: claims.Issuer, Metadata: cMD, Scopes: claims.Scopes, Roles: claims.Roles}, nil
}

func (p *jwtPlugin) WrapHandlerFunc(ctx context.Context, req server.Request, rsp interface{}) error {
	u, err := p.Inspect(ctx)
	if err != nil {
		u = auth2.AnonUser
	}
	ctx = context.WithValue(ctx, auth2.ContextUserKey{}, u)

	var defaultDenyOk bool
	for _, v := range p.verifiers {
		err, defaultDenyOk = v.Verify(ctx, u, req)
		if !defaultDenyOk {
			return err
		}
	}

	return err
}

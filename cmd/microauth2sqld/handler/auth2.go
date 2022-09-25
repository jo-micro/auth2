package handler

import (
	"context"
	"crypto/ed25519"
	"crypto/rsa"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"go-micro.dev/v4/errors"
	"go-micro.dev/v4/util/log"
	"google.golang.org/protobuf/types/known/emptypb"
	"jochum.dev/jo-micro/auth2"
	"jochum.dev/jo-micro/auth2/cmd/microauth2sqld/config"
	"jochum.dev/jo-micro/auth2/cmd/microauth2sqld/db"
	"jochum.dev/jo-micro/auth2/internal/argon2"
	"jochum.dev/jo-micro/auth2/internal/proto/authpb"
	"jochum.dev/jo-micro/auth2/plugins/verifier/endpointroles"
	"jochum.dev/jo-micro/auth2/shared/sjwt"
	"jochum.dev/jo-micro/components"
	"jochum.dev/jo-micro/logruscomponent"
	"jochum.dev/jo-micro/router"
)

type InitConfig struct {
	Audiences          []string
	RefreshTokenExpiry int64
	AccessTokenExpiry  int64

	AccessTokenPubKey   string
	AccessTokenPrivKey  string
	RefreshTokenPubKey  string
	RefreshTokenPrivKey string
}

type Handler struct {
	cReg                *components.Registry
	audiences           []string
	refreshTokenExpiry  int64
	accessTokenExpiry   int64
	accessTokenPubKey   any
	accessTokenPrivKey  any
	refreshTokenPubKey  any
	refreshTokenPrivKey any
}

func NewHandler() *Handler {
	return &Handler{}
}

func (h *Handler) Init(cReg *components.Registry, c InitConfig) error {
	h.cReg = cReg
	h.audiences = c.Audiences
	h.accessTokenExpiry = c.AccessTokenExpiry
	h.refreshTokenExpiry = c.RefreshTokenExpiry

	pub, priv, err := sjwt.DecodeKeyPair(c.AccessTokenPubKey, c.AccessTokenPrivKey)
	if err != nil {
		return err
	}
	h.accessTokenPubKey = pub
	h.accessTokenPrivKey = priv

	pub, priv, err = sjwt.DecodeKeyPair(c.RefreshTokenPubKey, c.RefreshTokenPrivKey)
	if err != nil {
		return err
	}
	h.refreshTokenPubKey = pub
	h.refreshTokenPrivKey = priv

	r := router.MustReg(h.cReg)
	r.Add(
		router.NewRoute(
			router.Method(router.MethodGet),
			router.Path("/"),
			router.Endpoint(authpb.AuthService.List),
			router.Params("limit", "offset"),
			router.AuthRequired(),
			router.RatelimitUser("1-S", "10-M"),
		),
		router.NewRoute(
			router.Method(router.MethodPost),
			router.Path("/login"),
			router.Endpoint(authpb.AuthService.Login),
			router.RatelimitClientIP("1-S", "10-M", "30-H", "100-D"),
		),
		router.NewRoute(
			router.Method(router.MethodPost),
			router.Path("/register"),
			router.Endpoint(authpb.AuthService.Register),
			router.RatelimitClientIP("1-M", "10-H", "50-D"),
		),
		router.NewRoute(
			router.Method(router.MethodPost),
			router.Path("/refresh"),
			router.Endpoint(authpb.AuthService.Refresh),
			router.RatelimitClientIP("1-M", "10-H", "50-D"),
		),
		router.NewRoute(
			router.Method(router.MethodDelete),
			router.Path("/:userId"),
			router.Endpoint(authpb.AuthService.Delete),
			router.Params("userId"),
			router.AuthRequired(),
			router.RatelimitUser("1-S", "10-M"),
		),
		router.NewRoute(
			router.Method(router.MethodGet),
			router.Path("/:userId"),
			router.Endpoint(authpb.AuthService.Detail),
			router.Params("userId"),
			router.AuthRequired(),
			router.RatelimitUser("100-M"),
		),
		router.NewRoute(
			router.Method(router.MethodPut),
			router.Path("/:userId/roles"),
			router.Endpoint(authpb.AuthService.UpdateRoles),
			router.Params("userId"),
			router.AuthRequired(),
			router.RatelimitUser("1-M"),
		),
	)

	authVerifier := endpointroles.NewVerifier(
		endpointroles.WithLogrus(logruscomponent.MustReg(h.cReg).Logger()),
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
	auth2.ClientAuthMustReg(h.cReg).Plugin().AddVerifier(authVerifier)

	return nil
}

func (h *Handler) Stop() error {
	return nil
}

func (h *Handler) List(ctx context.Context, in *authpb.ListRequest, out *authpb.UserListReply) error {
	results, err := db.UserList(h.cReg, ctx, in.Limit, in.Offset)
	if err != nil {
		return err
	}

	// Copy the data to the result
	for _, result := range results {
		out.Data = append(out.Data, &authpb.User{
			Id:       result.ID.String(),
			Username: result.Username,
			Email:    result.Email,
		})
	}

	return nil
}

func (h *Handler) Detail(ctx context.Context, in *authpb.UserIDRequest, out *authpb.User) error {
	result, err := db.UserDetail(h.cReg, ctx, in.UserId)
	if err != nil {
		return err
	}

	out.Id = result.ID.String()
	out.Email = result.Email
	out.Username = result.Username
	out.Roles = result.Roles

	return nil
}

func (h *Handler) Delete(ctx context.Context, in *authpb.UserIDRequest, out *emptypb.Empty) error {
	err := db.UserDelete(h.cReg, ctx, in.UserId)
	if err != nil {
		return err
	}

	return nil
}

func (h *Handler) UpdateRoles(ctx context.Context, in *authpb.UpdateRolesRequest, out *authpb.User) error {
	result, err := db.UserUpdateRoles(h.cReg, ctx, in.UserId, in.Roles)
	if err != nil {
		return err
	}

	out.Id = result.ID.String()
	out.Email = result.Email
	out.Username = result.Username
	out.Roles = result.Roles

	return nil
}

func (h *Handler) Register(ctx context.Context, in *authpb.RegisterRequest, out *authpb.User) error {
	if in.Username == auth2.ROLE_SERVICE {
		return errors.New(config.Name, "User already exists", http.StatusConflict)
	}

	hash, err := argon2.Hash(in.Password, argon2.DefaultParams)
	if err != nil {
		return err
	}

	result, err := db.UserCreate(h.cReg, ctx, in.Username, hash, in.Email, []string{auth2.ROLE_USER})
	if err != nil {
		return errors.New(config.Name, "User already exists", http.StatusConflict)
	}

	out.Id = result.ID.String()
	out.Email = result.Email
	out.Username = result.Username
	out.Roles = result.Roles

	return nil
}

func (h *Handler) genTokens(ctx context.Context, user *db.User, out *authpb.Token) error {
	// Create the Claims
	refreshClaims := sjwt.JWTClaims{
		RegisteredClaims: &jwt.RegisteredClaims{
			Issuer:    config.Name,
			Subject:   user.Username,
			Audience:  h.audiences,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Duration(h.accessTokenExpiry) * time.Second)),
			NotBefore: jwt.NewNumericDate(time.Now()),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ID:        user.ID.String(),
		},
	}
	if err := refreshClaims.Valid(); err != nil {
		return err
	}

	var (
		accessToken  *jwt.Token
		refreshToken *jwt.Token
	)

	switch h.refreshTokenPrivKey.(type) {
	case *rsa.PrivateKey:
		refreshToken = jwt.NewWithClaims(jwt.SigningMethodRS512, refreshClaims)
	case ed25519.PrivateKey:
		refreshToken = jwt.NewWithClaims(jwt.SigningMethodEdDSA, refreshClaims)
	}
	refreshSignedToken, err := refreshToken.SignedString(h.refreshTokenPrivKey)
	if err != nil {
		return err
	}

	// Create the AccessToken
	accessClaims := sjwt.JWTClaims{
		RegisteredClaims: &jwt.RegisteredClaims{
			Issuer:    config.Name,
			Subject:   user.Username,
			Audience:  h.audiences,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Duration(h.accessTokenExpiry) * time.Second)),
			NotBefore: jwt.NewNumericDate(time.Now()),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ID:        user.ID.String(),
		},
		Roles: user.Roles,
	}
	if err := accessClaims.Valid(); err != nil {
		return err
	}

	switch h.accessTokenPrivKey.(type) {
	case *rsa.PrivateKey:
		accessToken = jwt.NewWithClaims(jwt.SigningMethodRS512, accessClaims)
	case ed25519.PrivateKey:
		accessToken = jwt.NewWithClaims(jwt.SigningMethodEdDSA, accessClaims)
	}
	accessSignedToken, err := accessToken.SignedString(h.accessTokenPrivKey)
	if err != nil {
		return err
	}

	out.Id = user.ID.String()
	out.RefreshToken = refreshSignedToken
	out.RefreshTokenExpiresAt = refreshClaims.ExpiresAt.Unix()
	out.AccessToken = accessSignedToken
	out.AccessTokenExpiresAt = accessClaims.ExpiresAt.Unix()

	return nil
}

func (h *Handler) Login(ctx context.Context, in *authpb.LoginRequest, out *authpb.Token) error {
	user, err := db.UserFindByUsername(h.cReg, ctx, in.Username)
	if err != nil {
		log.Error(err)
		return errors.New(config.Name, "Wrong username or password", http.StatusUnauthorized)
	}

	ok, err := argon2.Verify(in.Password, user.Password)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New(config.Name, "Wrong username or password", http.StatusUnauthorized)
	}

	return h.genTokens(ctx, user, out)
}

func (h *Handler) Refresh(ctx context.Context, in *authpb.RefreshTokenRequest, out *authpb.Token) error {
	claims := sjwt.JWTClaims{}
	_, err := jwt.ParseWithClaims(in.RefreshToken, &claims, func(token *jwt.Token) (interface{}, error) {
		return h.refreshTokenPubKey, nil
	})
	if err != nil {
		return errors.New(config.Name, fmt.Sprintf("checking the RefreshToken: %s", err), http.StatusBadRequest)
	}

	// Check claims (expiration)
	if err = claims.Valid(); err != nil {
		return fmt.Errorf("claims invalid: %s", err)
	}

	user, err := db.UserFindById(h.cReg, ctx, claims.ID)
	if err != nil {
		return errors.New(config.Name, fmt.Sprintf("error fetching the user: %s", err), http.StatusUnauthorized)
	}

	return h.genTokens(ctx, user, out)
}

func (s *Handler) Inspect(ctx context.Context, in *emptypb.Empty, out *authpb.JWTClaims) error {
	u := ctx.Value("user")

	if u == nil {
		return errors.BadRequest("auth2/handler.Inspect|no user", "no user found in context")
	}

	u2 := u.(auth2.User)

	out.Id = u2.Id
	out.Type = u2.Type
	out.Issuer = u2.Issuer
	out.Metadata = u2.Metadata
	out.Roles = u2.Roles
	out.Scopes = u2.Scopes

	return nil
}

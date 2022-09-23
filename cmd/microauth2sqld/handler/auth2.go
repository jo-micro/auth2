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
	"jochum.dev/jo-micro/auth2/shared/sjwt"
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

func (h *Handler) Init(c InitConfig) error {
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

	return nil
}

func (h *Handler) Stop() error {
	return nil
}

func (s *Handler) List(ctx context.Context, in *authpb.ListRequest, out *authpb.UserListReply) error {
	results, err := db.UserList(ctx, in.Limit, in.Offset)
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

func (s *Handler) Detail(ctx context.Context, in *authpb.UserIDRequest, out *authpb.User) error {
	result, err := db.UserDetail(ctx, in.UserId)
	if err != nil {
		return err
	}

	out.Id = result.ID.String()
	out.Email = result.Email
	out.Username = result.Username
	out.Roles = result.Roles

	return nil
}

func (s *Handler) Delete(ctx context.Context, in *authpb.UserIDRequest, out *emptypb.Empty) error {
	err := db.UserDelete(ctx, in.UserId)
	if err != nil {
		return err
	}

	return nil
}

func (s *Handler) UpdateRoles(ctx context.Context, in *authpb.UpdateRolesRequest, out *authpb.User) error {
	result, err := db.UserUpdateRoles(ctx, in.UserId, in.Roles)
	if err != nil {
		return err
	}

	out.Id = result.ID.String()
	out.Email = result.Email
	out.Username = result.Username
	out.Roles = result.Roles

	return nil
}

func (s *Handler) Register(ctx context.Context, in *authpb.RegisterRequest, out *authpb.User) error {
	if in.Username == auth2.ROLE_SERVICE {
		return errors.New(config.Name, "User already exists", http.StatusConflict)
	}

	hash, err := argon2.Hash(in.Password, argon2.DefaultParams)
	if err != nil {
		return err
	}

	result, err := db.UserCreate(ctx, in.Username, hash, in.Email, []string{auth2.ROLE_USER})
	if err != nil {
		return errors.New(config.Name, "User already exists", http.StatusConflict)
	}

	out.Id = result.ID.String()
	out.Email = result.Email
	out.Username = result.Username
	out.Roles = result.Roles

	return nil
}

func (s *Handler) genTokens(ctx context.Context, user *db.User, out *authpb.Token) error {
	// Create the Claims
	refreshClaims := sjwt.JWTClaims{
		RegisteredClaims: &jwt.RegisteredClaims{
			Issuer:    config.Name,
			Subject:   user.Username,
			Audience:  s.audiences,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Duration(s.accessTokenExpiry) * time.Second)),
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

	switch s.refreshTokenPrivKey.(type) {
	case *rsa.PrivateKey:
		refreshToken = jwt.NewWithClaims(jwt.SigningMethodRS512, refreshClaims)
	case ed25519.PrivateKey:
		refreshToken = jwt.NewWithClaims(jwt.SigningMethodEdDSA, refreshClaims)
	}
	refreshSignedToken, err := refreshToken.SignedString(s.refreshTokenPrivKey)
	if err != nil {
		return err
	}

	// Create the AccessToken
	accessClaims := sjwt.JWTClaims{
		RegisteredClaims: &jwt.RegisteredClaims{
			Issuer:    config.Name,
			Subject:   user.Username,
			Audience:  s.audiences,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Duration(s.accessTokenExpiry) * time.Second)),
			NotBefore: jwt.NewNumericDate(time.Now()),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ID:        user.ID.String(),
		},
		Roles: user.Roles,
	}
	if err := accessClaims.Valid(); err != nil {
		return err
	}

	switch s.accessTokenPrivKey.(type) {
	case *rsa.PrivateKey:
		accessToken = jwt.NewWithClaims(jwt.SigningMethodRS512, accessClaims)
	case ed25519.PrivateKey:
		accessToken = jwt.NewWithClaims(jwt.SigningMethodEdDSA, accessClaims)
	}
	accessSignedToken, err := accessToken.SignedString(s.accessTokenPrivKey)
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

func (s *Handler) Login(ctx context.Context, in *authpb.LoginRequest, out *authpb.Token) error {
	user, err := db.UserFindByUsername(ctx, in.Username)
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

	return s.genTokens(ctx, user, out)
}

func (s *Handler) Refresh(ctx context.Context, in *authpb.RefreshTokenRequest, out *authpb.Token) error {
	claims := sjwt.JWTClaims{}
	_, err := jwt.ParseWithClaims(in.RefreshToken, &claims, func(token *jwt.Token) (interface{}, error) {
		return s.refreshTokenPubKey, nil
	})
	if err != nil {
		return errors.New(config.Name, fmt.Sprintf("checking the RefreshToken: %s", err), http.StatusBadRequest)
	}

	// Check claims (expiration)
	if err = claims.Valid(); err != nil {
		return fmt.Errorf("claims invalid: %s", err)
	}

	user, err := db.UserFindById(ctx, claims.ID)
	if err != nil {
		return errors.New(config.Name, fmt.Sprintf("error fetching the user: %s", err), http.StatusUnauthorized)
	}

	return s.genTokens(ctx, user, out)
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

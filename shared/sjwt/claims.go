package sjwt

import "github.com/golang-jwt/jwt/v4"

type JWTClaims struct {
	*jwt.RegisteredClaims
	Type   string   `json:"type,omitempty"`
	Roles  []string `json:"roles,omitempty"`
	Scopes []string `json:"scopes,omitempty"`
}

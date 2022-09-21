package auth2

type User struct {
	Id       string            `json:"id,omitempty"`
	Type     string            `json:"type,omitempty"`
	Issuer   string            `json:"issuer,omitempty"`
	Metadata map[string]string `json:"metadata,omitempty"`
	Scopes   []string          `json:"scopes,omitempty"`
	Roles    []string          `json:"roles,omitempty"`
}

// AnonUser will be used when theres no user
var AnonUser = &User{
	Id:     "00000000-0000-0000-0000-000000000000",
	Type:   "user",
	Issuer: "nobody",
	Metadata: map[string]string{
		"Subject": "service",
	},
	Scopes: []string{},
	Roles:  []string{ROLE_ANONYMOUS},
}

var ServiceUser = &User{
	Id:     "00000000-0000-0000-0000-000000000001",
	Type:   "service",
	Issuer: "",
	Scopes: []string{},
	Roles:  []string{ROLE_SERVICE},
}

// ContextUserKey is the key in the context for the User value.
type ContextUserKey struct{}

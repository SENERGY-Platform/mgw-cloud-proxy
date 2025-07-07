package jwt_util

type JWT struct {
	Exp               int            `json:"exp"`
	Iat               int            `json:"iat"`
	AuthTime          int            `json:"auth_time"`
	Jti               string         `json:"jti"`
	Iss               string         `json:"iss"`
	Aud               string         `json:"aud"`
	Sub               string         `json:"sub"`
	Typ               string         `json:"typ"`
	Azp               string         `json:"azp"`
	Sid               string         `json:"sid"`
	AllowedOrigins    []string       `json:"allowed-origins"`
	RealmAccess       RealmAccess    `json:"realm_access"`
	ResourceAccess    ResourceAccess `json:"resource_access"`
	Scope             string         `json:"scope"`
	EmailVerified     bool           `json:"email_verified"`
	Roles             []string       `json:"roles"`
	Name              string         `json:"name"`
	Groups            []string       `json:"groups"`
	PreferredUsername string         `json:"preferred_username"`
	GivenName         string         `json:"given_name"`
	Locale            string         `json:"locale"`
	FamilyName        string         `json:"family_name"`
	Email             string         `json:"email"`
}

type RealmAccess struct {
	Roles []string `json:"roles"`
}

type ResourceAccess struct {
	Account Account `json:"account"`
}

type Account struct {
	Roles []string `json:"roles"`
}

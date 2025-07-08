package jwt

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
)

func Parse(t string) (JWT, error) {
	parts := strings.Split(t, ".")
	if len(parts) != 3 {
		return JWT{}, errors.New("malformed access token")
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return JWT{}, err
	}
	var jwt JWT
	if err = json.Unmarshal(b, &jwt); err != nil {
		return JWT{}, err
	}
	return jwt, nil
}

func GetSubject(t string) (string, error) {
	jwt, err := Parse(t)
	if err != nil {
		return "", err
	}
	return jwt.Sub, nil
}

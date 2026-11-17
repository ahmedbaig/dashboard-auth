package tokens

import (
	"crypto/ed25519"
	"time"

	"github.com/ahmedbaig/go-backend-types"
	"github.com/golang-jwt/jwt/v5"
)

type Private struct {
	Key ed25519.PrivateKey
	ID  string
}

type Public struct {
	Key ed25519.PublicKey
	ID  string
}

type AccessClaims struct {
	SID string `json:"sid"`
	jwt.RegisteredClaims
}

type InternalClaims struct {
	SID  string     `json:"sid"`
	User types.User `json:"usr"`
	jwt.RegisteredClaims
}

type Signer struct {
	key    Private
	issuer string
	now    func() time.Time
}

type Verifier struct {
	keys   map[string]Public
	issuer string
	now    func() time.Time
}

package tokens

import (
	"errors"
	"strconv"
	"time"

	"github.com/ahmedbaig/dashboard-auth/internal/constants"
	"github.com/ahmedbaig/go-backend-types"
	"github.com/golang-jwt/jwt/v5"
)

func NewSigner(key Private, issuer string) *Signer {
	return &Signer{key: key, issuer: issuer, now: time.Now}
}

func (s *Signer) sign(claims jwt.Claims) (string, error) {
	t := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	t.Header["kid"] = s.key.ID
	return t.SignedString(s.key.Key)
}

func (s *Signer) registered(subject, audience string, ttl time.Duration) (jwt.RegisteredClaims, time.Time) {
	now := s.now()
	exp := now.Add(ttl)
	return jwt.RegisteredClaims{
		Issuer:    s.issuer,
		Subject:   subject,
		Audience:  jwt.ClaimStrings{audience},
		IssuedAt:  jwt.NewNumericDate(now),
		NotBefore: jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(exp),
	}, exp
}

func (s *Signer) Access(userID, sid string, ttl time.Duration) (string, time.Time, error) {
	rc, exp := s.registered(userID, constants.AudienceAccess, ttl)
	tok, err := s.sign(AccessClaims{SID: sid, RegisteredClaims: rc})
	return tok, exp, err
}

func (s *Signer) Internal(user types.User, sid string, ttl time.Duration) (string, error) {
	rc, _ := s.registered(strconv.FormatInt(user.ID, 10), constants.AudienceInternal, ttl)
	return s.sign(InternalClaims{SID: sid, User: user, RegisteredClaims: rc})
}

func NewVerifier(issuer string, pubs ...Public) *Verifier {
	m := make(map[string]Public, len(pubs))
	for _, p := range pubs {
		m[p.ID] = p
	}
	return &Verifier{keys: m, issuer: issuer, now: time.Now}
}

func (v *Verifier) parse(raw, audience string, claims jwt.Claims) error {
	_, err := jwt.ParseWithClaims(raw, claims, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		k, ok := v.keys[kid]
		if !ok {
			return nil, ErrInvalid
		}
		return k.Key, nil
	},
		jwt.WithValidMethods([]string{jwt.SigningMethodEdDSA.Alg()}),
		jwt.WithAudience(audience),
		jwt.WithIssuer(v.issuer),
		jwt.WithExpirationRequired(),
		jwt.WithTimeFunc(v.now),
	)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, jwt.ErrTokenExpired):
		return ErrExpired
	default:
		return ErrInvalid
	}
}

func (v *Verifier) Access(raw string) (AccessClaims, error) {
	var c AccessClaims
	err := v.parse(raw, constants.AudienceAccess, &c)
	if err == nil && (c.SID == "" || c.Subject == "") {
		err = ErrInvalid
	}
	return c, err
}

func (v *Verifier) Internal(raw string) (InternalClaims, error) {
	var c InternalClaims
	err := v.parse(raw, constants.AudienceInternal, &c)
	if err == nil && (c.SID == "" || c.User.ID == 0) {
		err = ErrInvalid
	}
	return c, err
}

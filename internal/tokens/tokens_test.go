package tokens

import (
	"errors"
	"testing"
	"time"

	"github.com/ahmedbaig/go-backend-types"
)

func TestAccessRoundTripAndExpiry(t *testing.T) {
	priv, pub := Generate()
	s := NewSigner(priv, "dashboard-auth")
	v := NewVerifier("dashboard-auth", pub)
	tok, _, err := s.Access("7", "sid-1", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	c, err := v.Access(tok)
	if err != nil || c.SID != "sid-1" || c.Subject != "7" {
		t.Fatalf("claims %+v %v", c, err)
	}
	v.now = func() time.Time { return time.Now().Add(2 * time.Minute) }
	if _, err := v.Access(tok); !errors.Is(err, ErrExpired) {
		t.Fatalf("want expired, got %v", err)
	}
}

func TestRejectsOtherKeysAudiencesAndIssuers(t *testing.T) {
	priv, pub := Generate()
	other, _ := Generate()
	v := NewVerifier("dashboard-auth", pub)

	forged, _, _ := NewSigner(other, "dashboard-auth").Access("7", "sid", time.Minute)
	if _, err := v.Access(forged); !errors.Is(err, ErrInvalid) {
		t.Fatalf("other key: %v", err)
	}
	internal, _ := NewSigner(priv, "dashboard-auth").Internal(types.User{ID: 7}, "sid", time.Minute)
	if _, err := v.Access(internal); !errors.Is(err, ErrInvalid) {
		t.Fatalf("internal token used as access: %v", err)
	}
	wrongIssuer, _, _ := NewSigner(priv, "someone-else").Access("7", "sid", time.Minute)
	if _, err := v.Access(wrongIssuer); !errors.Is(err, ErrInvalid) {
		t.Fatalf("issuer: %v", err)
	}
}

func TestInternalCarriesUser(t *testing.T) {
	priv, pub := Generate()
	tok, err := NewSigner(priv, "dashboard-edge").Internal(types.User{ID: 3, Email: "a@b.c", Features: []string{"weather:read"}}, "sid", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewVerifier("dashboard-edge", pub).Internal(tok)
	if err != nil || c.User.Email != "a@b.c" || !c.User.Can("weather:read") {
		t.Fatalf("%+v %v", c, err)
	}
}

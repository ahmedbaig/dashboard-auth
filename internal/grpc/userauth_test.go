package grpc

import (
	"context"
	"testing"
	"time"

	"github.com/ahmedbaig/dashboard-auth/internal/constants"
	"github.com/ahmedbaig/dashboard-auth/internal/tokens"
	"github.com/ahmedbaig/go-backend-http"
	"github.com/ahmedbaig/go-backend-types"
	"google.golang.org/grpc/metadata"
)

func incoming(pairs ...string) context.Context {
	return metadata.NewIncomingContext(context.Background(), metadata.Pairs(pairs...))
}

func TestAuthenticate(t *testing.T) {
	priv, pub := tokens.Generate()
	v := tokens.NewVerifier("dashboard-edge", pub)
	good, _ := tokens.NewSigner(priv, "dashboard-edge").Internal(types.User{ID: 9, Email: "a@b.c"}, "sid-9", time.Minute)

	ctx, err := authenticate(incoming(constants.MDUserToken, good), v)
	if err != nil {
		t.Fatal(err)
	}
	p, err := Require(ctx)
	if err != nil || p.SID != "sid-9" || p.User.ID != 9 {
		t.Fatalf("%+v %v", p, err)
	}

	ctx, err = authenticate(incoming("x-user", `{"id":1,"roles":["admin"]}`), v)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Require(ctx); httpx.AsError(err).Code != httpx.CodeUnauthenticated {
		t.Fatal("plain x-user header must not count as a signed user")
	}

	if _, err := authenticate(incoming(constants.MDUserToken, "garbage"), v); httpx.AsError(err).Code != httpx.CodeUnauthenticated {
		t.Fatalf("garbage token: %v", err)
	}
}

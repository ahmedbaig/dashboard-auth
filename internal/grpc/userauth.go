package grpc

import (
	"context"
	"errors"
	"log/slog"

	"github.com/ahmedbaig/dashboard-auth/internal/constants"
	"github.com/ahmedbaig/dashboard-auth/internal/tokens"
	"github.com/ahmedbaig/go-backend-http"
	"github.com/ahmedbaig/go-backend-logging"
	"github.com/ahmedbaig/go-backend-proto/grpcx"
	"github.com/ahmedbaig/go-backend-types"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

func WithPrincipal(ctx context.Context, p Principal) context.Context {
	ctx = types.WithUser(ctx, p.User)
	ctx = logging.WithAttrs(ctx, slog.Int64("userId", p.User.ID), slog.String("email", p.User.Email), slog.Any("roles", p.User.Roles), slog.String("sid", p.SID))
	return context.WithValue(ctx, principalKey{}, p)
}

func From(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(principalKey{}).(Principal)
	return p, ok
}

func Require(ctx context.Context) (Principal, error) {
	if p, ok := From(ctx); ok {
		return p, nil
	}
	return Principal{}, httpx.E(httpx.CodeUnauthenticated)
}

func RequireRole(ctx context.Context, role string) (Principal, error) {
	p, err := Require(ctx)
	if err != nil {
		return p, err
	}
	if !p.User.Has(role) {
		return p, httpx.E(httpx.CodeForbidden).WithMessage("Missing role " + role)
	}
	return p, nil
}

func Metadata(ctx context.Context, key string) string {
	md, _ := metadata.FromIncomingContext(ctx)
	if v := md.Get(key); len(v) > 0 {
		return v[0]
	}
	return ""
}

func authenticate(ctx context.Context, v *tokens.Verifier) (context.Context, error) {
	raw := Metadata(ctx, constants.MDUserToken)
	if raw == "" {
		return ctx, nil
	}
	c, err := v.Internal(raw)
	if err != nil {
		if errors.Is(err, tokens.ErrExpired) {
			return ctx, httpx.E(httpx.CodeSessionExpired)
		}
		return ctx, httpx.E(httpx.CodeUnauthenticated)
	}
	return WithPrincipal(ctx, Principal{User: c.User, SID: c.SID}), nil
}

func ServerOptions(v *tokens.Verifier) []grpc.ServerOption {
	return []grpc.ServerOption{
		grpc.ChainUnaryInterceptor(func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, next grpc.UnaryHandler) (any, error) {
			ctx, err := authenticate(ctx, v)
			if err != nil {
				return nil, grpcx.ToStatus(err)
			}
			return next(ctx, req)
		}),
		grpc.ChainStreamInterceptor(func(srv any, ss grpc.ServerStream, _ *grpc.StreamServerInfo, next grpc.StreamHandler) error {
			ctx, err := authenticate(ss.Context(), v)
			if err != nil {
				return grpcx.ToStatus(err)
			}
			return next(srv, &stream{ServerStream: ss, ctx: ctx})
		}),
	}
}

func (s *stream) Context() context.Context { return s.ctx }

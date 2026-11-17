package session

import (
	"context"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/ahmedbaig/dashboard-auth/internal/constants"
	"github.com/ahmedbaig/dashboard-auth/internal/tokens"
	"github.com/ahmedbaig/go-backend-http"
	"github.com/ahmedbaig/go-backend-logging"
	"github.com/ahmedbaig/go-backend-types"
)

func WithCaller(ctx context.Context, c Caller) context.Context {
	ctx = types.WithUser(ctx, c.User)
	ctx = logging.WithAttrs(ctx, slog.Int64("userId", c.User.ID), slog.String("email", c.User.Email), slog.Any("roles", c.User.Roles), slog.String("sid", c.SID))
	return context.WithValue(ctx, callerKey{}, c)
}

func CallerFrom(ctx context.Context) (Caller, bool) {
	c, ok := ctx.Value(callerKey{}).(Caller)
	return c, ok
}

func RequireCaller(ctx context.Context) (Caller, error) {
	if c, ok := CallerFrom(ctx); ok {
		return c, nil
	}
	return Caller{}, httpx.E(httpx.CodeUnauthenticated)
}

func bearer(r *http.Request) string {
	h := r.Header.Get(constants.HeaderAuthorization)
	if n := len(constants.BearerPrefix); len(h) > n && strings.EqualFold(h[:n], constants.BearerPrefix) {
		return strings.TrimSpace(h[n:])
	}
	return ""
}

func (s *Store) Authenticate(v *tokens.Verifier) httpx.Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw := bearer(r)
			if raw == "" {
				next.ServeHTTP(w, r)
				return
			}
			ctx := context.WithValue(r.Context(), attemptKey{}, true)
			c, err := v.Access(raw)
			if err != nil {
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}
			rec, found, err := s.Get(ctx, c.SID)
			if err != nil {
				httpx.WriteError(w, r, httpx.E(httpx.CodeUnavailable).WithMessage("Sessions are unavailable").Wrap(err))
				return
			}
			if found && strconv.FormatInt(rec.UserID, 10) == c.Subject {
				ctx = WithCaller(ctx, Caller{User: rec.User, SID: rec.SID})
			}
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func Require() httpx.Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, ok := CallerFrom(r.Context()); ok {
				next.ServeHTTP(w, r)
				return
			}
			code := httpx.CodeUnauthenticated
			if tried, _ := r.Context().Value(attemptKey{}).(bool); tried {
				code = httpx.CodeSessionExpired
			}
			httpx.WriteError(w, r, httpx.E(code))
		})
	}
}

func ClientFrom(r *http.Request) Client {
	return Client{IP: httpx.ClientIP(r, nil), UserAgent: r.UserAgent()}
}

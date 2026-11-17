package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/ahmedbaig/dashboard-auth/api"
	"github.com/ahmedbaig/dashboard-auth/internal/constants"
	"github.com/ahmedbaig/dashboard-auth/internal/session"
	"github.com/ahmedbaig/dashboard-auth/internal/tokens"
	"github.com/ahmedbaig/go-backend-http"
	"github.com/ahmedbaig/go-backend-logging"
	"github.com/ahmedbaig/go-backend-types"
)

func NewAuthService(users *UsersService, store *session.Store, lockout *session.Lockout, signer *tokens.Signer, o AuthOptions) (*AuthService, error) {
	if o.Argon2 == (Argon2{}) {
		o.Argon2 = DefaultArgon2
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	dummy, err := o.Argon2.Hash(session.RandomToken(16))
	if err != nil {
		return nil, err
	}
	return &AuthService{users: users, store: store, lockout: lockout, signer: signer, o: o, dummy: dummy, now: o.Now}, nil
}

func (s *AuthService) issue(r session.Record, refresh string) (issued, error) {
	access, exp, err := s.signer.Access(strconv.FormatInt(r.UserID, 10), r.SID, s.o.AccessTTL)
	if err != nil {
		return issued{}, err
	}
	return issued{Access: access, AccessExp: exp, Refresh: refresh, RefreshExp: s.now().Add(s.store.TTL())}, nil
}

func (s *AuthService) tokens(t issued) api.Tokens {
	now := s.now()
	return api.Tokens{
		AccessToken:      t.Access,
		AccessExpiresIn:  int64(t.AccessExp.Sub(now).Seconds()),
		RefreshToken:     t.Refresh,
		RefreshExpiresIn: int64(t.RefreshExp.Sub(now).Seconds()),
	}
}

func (s *AuthService) verify(ctx context.Context, email, password string) (Account, error) {
	acc, err := s.users.ByEmail(ctx, email)
	if err != nil && !isNotFound(err) {
		return acc, err
	}
	hash, reason := s.dummy, "unknown email"
	if err == nil {
		h, herr := s.users.PasswordHash(ctx, acc.User.ID)
		if herr != nil && !isNotFound(herr) {
			return acc, herr
		}
		reason = "no password set"
		if herr == nil {
			hash, reason = h, "wrong password"
		}
	}
	ok, verr := VerifyPassword(hash, password)
	if err != nil || verr != nil || !ok || hash == s.dummy {
		attrs := []any{slog.String("loginEmail", email), slog.String("reason", reason)}
		if acc.User.ID != 0 {
			attrs = append(attrs, slog.Int64("targetUserId", acc.User.ID))
		}
		httpx.LoggerFrom(ctx).InfoContext(ctx, "login failed", attrs...)
		if ferr := s.lockout.Fail(ctx, email); ferr != nil {
			return acc, unavailable(ferr)
		}
		return acc, errCredentials
	}
	return acc, nil
}

func (s *AuthService) Login(ctx context.Context, in api.LoginRequest, client session.Client) (api.LoginResponse, error) {
	email := NormalizeEmail(in.Email)
	left, err := s.lockout.Locked(ctx, email)
	if err != nil {
		return api.LoginResponse{}, unavailable(err)
	}
	if left > 0 {
		mins := max(int(left.Round(time.Minute).Minutes()), 1)
		httpx.LoggerFrom(ctx).WarnContext(ctx, "login blocked, email locked", slog.String("loginEmail", email), slog.Int("retryInMin", mins))
		return api.LoginResponse{}, httpx.E(httpx.CodeRateLimited).WithMessage(fmt.Sprintf("Too many attempts. Try again in %d min", mins))
	}
	acc, err := s.verify(ctx, email, in.Password)
	if err != nil {
		return api.LoginResponse{}, err
	}
	if acc.Disabled {
		httpx.LoggerFrom(ctx).WarnContext(ctx, "login refused, account disabled", slog.Int64("targetUserId", acc.User.ID))
		return api.LoginResponse{}, errDisabled
	}
	_ = s.lockout.Clear(ctx, email)

	device, browser := describeAgent(client.UserAgent)
	now := s.now()
	sid := session.NewSID()
	refresh, rhash := session.NewRefresh(sid)
	rec := session.Record{
		SID: sid, UserID: acc.User.ID, User: acc.User,
		IP: client.IP, UserAgent: client.UserAgent, Device: device, Browser: browser,
		CreatedAt: now, LastSeenAt: now, RefreshHash: rhash,
	}
	if err := s.store.Create(ctx, rec); err != nil {
		return api.LoginResponse{}, unavailable(err)
	}
	ctx = withUser(ctx, acc.User, sid)
	if err := s.users.TouchLogin(ctx, acc.User.ID); err != nil {
		httpx.LoggerFrom(ctx).WarnContext(ctx, "last login not saved", slog.Any("error", err))
	}
	t, err := s.issue(rec, refresh)
	if err != nil {
		return api.LoginResponse{}, err
	}
	httpx.LoggerFrom(ctx).InfoContext(ctx, "login", slog.String("device", device), slog.String("browser", browser))
	return api.LoginResponse{User: acc.User, Session: toSession(rec, sid), Tokens: s.tokens(t)}, nil
}

func (s *AuthService) Refresh(ctx context.Context, refreshToken string, client session.Client) (api.RefreshResponse, error) {
	sid, hash, ok := session.SplitRefresh(refreshToken)
	if !ok {
		httpx.LoggerFrom(ctx).InfoContext(ctx, "refresh token malformed")
		return api.RefreshResponse{}, errSignIn
	}
	reason, revoked, err := s.store.Revoked(ctx, sid)
	if err != nil {
		return api.RefreshResponse{}, unavailable(err)
	}
	if revoked {
		httpx.LoggerFrom(ctx).WarnContext(ctx, "refresh on revoked session", slog.String("sid", sid), slog.String("reason", reason))
		return api.RefreshResponse{}, errSignIn.WithSupportActions("Session ended: " + reason)
	}

	rot, err := s.store.Rotate(ctx, sid, hash, s.o.RefreshGrace, func(cur session.Record) (session.Record, []byte, error) {
		acc, err := s.users.ByID(ctx, cur.UserID)
		if err != nil {
			return cur, nil, err
		}
		if acc.Disabled {
			return cur, nil, errDisabled
		}
		next := cur
		next.User = acc.User
		next.LastSeenAt = s.now()
		if client.IP != "" {
			next.IP = client.IP
		}
		refresh, rhash := session.NewRefresh(sid)
		next.RefreshHash = rhash
		t, err := s.issue(next, refresh)
		if err != nil {
			return cur, nil, err
		}
		b, err := json.Marshal(t)
		return next, b, err
	})
	switch {
	case errors.Is(err, session.ErrSessionGone):
		httpx.LoggerFrom(ctx).InfoContext(ctx, "refresh on expired session", slog.String("sid", sid))
		return api.RefreshResponse{}, errSignIn
	case errors.Is(err, session.ErrReuse):
		httpx.LoggerFrom(ctx).WarnContext(ctx, "refresh token reuse, revoking session", slog.String("sid", sid), slog.Int64("targetUserId", rot.Record.UserID))
		if rot.Record.SID != "" {
			if rerr := s.store.Revoke(ctx, rot.Record, constants.ReasonReuse); rerr != nil {
				return api.RefreshResponse{}, unavailable(rerr)
			}
		}
		return api.RefreshResponse{}, errSignIn
	case errors.Is(err, errDisabled):
		httpx.LoggerFrom(ctx).WarnContext(ctx, "refresh refused, account disabled, revoking session", slog.String("sid", sid), slog.Int64("targetUserId", rot.Record.UserID))
		if rot.Record.SID != "" {
			_ = s.store.Revoke(ctx, rot.Record, constants.ReasonDisabled)
		}
		return api.RefreshResponse{}, errDisabled
	case err != nil:
		if httpx.AsError(err).Code == httpx.CodeInternal {
			return api.RefreshResponse{}, unavailable(err)
		}
		return api.RefreshResponse{}, err
	}
	var t issued
	if err := json.Unmarshal(rot.Payload, &t); err != nil {
		return api.RefreshResponse{}, err
	}
	ctx = withUser(ctx, rot.Record.User, sid)
	httpx.LoggerFrom(ctx).InfoContext(ctx, "session refreshed")
	return api.RefreshResponse{User: rot.Record.User, Tokens: s.tokens(t)}, nil
}

func (s *AuthService) Logout(ctx context.Context, caller *session.Caller, refreshToken string) error {
	sid := ""
	if caller != nil {
		sid = caller.SID
	} else if rsid, hash, ok := session.SplitRefresh(refreshToken); ok {
		r, found, err := s.store.Get(ctx, rsid)
		if err != nil {
			return unavailable(err)
		}
		if found && (r.RefreshHash == hash || r.PrevHash == hash) {
			sid = rsid
		}
	}
	if sid == "" {
		httpx.LoggerFrom(ctx).InfoContext(ctx, "logout without a valid session")
		return nil
	}
	r, found, err := s.store.Get(ctx, sid)
	if err != nil {
		return unavailable(err)
	}
	if !found {
		httpx.LoggerFrom(ctx).InfoContext(ctx, "logout on missing session", slog.String("sid", sid))
		return nil
	}
	if err := s.store.Revoke(ctx, r, constants.ReasonSignedOut); err != nil {
		return unavailable(err)
	}
	ctx = withUser(ctx, r.User, sid)
	httpx.LoggerFrom(ctx).InfoContext(ctx, "logout")
	return nil
}

func withUser(ctx context.Context, u types.User, sid string) context.Context {
	return logging.WithAttrs(ctx, slog.Int64("userId", u.ID), slog.String("email", u.Email), slog.Any("roles", u.Roles), slog.String("sid", sid))
}

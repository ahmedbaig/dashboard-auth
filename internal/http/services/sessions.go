package services

import (
	"context"
	"log/slog"

	"github.com/ahmedbaig/dashboard-auth/api"
	"github.com/ahmedbaig/dashboard-auth/internal/constants"
	"github.com/ahmedbaig/dashboard-auth/internal/session"
	"github.com/ahmedbaig/go-backend-http"
	"github.com/ahmedbaig/go-backend-types"
)

func NewSessionsService(store *session.Store) *SessionsService {
	return &SessionsService{store: store}
}

func toSession(r session.Record, current string) api.Session {
	return api.Session{
		SID: r.SID, Device: r.Device, Browser: r.Browser, IP: r.IP,
		CreatedAt: r.CreatedAt, LastSeenAt: r.LastSeenAt, Current: r.SID == current,
	}
}

func (s *SessionsService) current(ctx context.Context, c session.Caller) (session.Record, error) {
	r, found, err := s.store.Get(ctx, c.SID)
	if err != nil {
		return r, unavailable(err)
	}
	if !found {
		httpx.LoggerFrom(ctx).InfoContext(ctx, "caller session gone")
		return r, errSignIn
	}
	if r.UserID != c.User.ID {
		httpx.LoggerFrom(ctx).WarnContext(ctx, "caller session belongs to another user", slog.Int64("targetUserId", r.UserID))
		return r, errSignIn
	}
	return r, nil
}

func (s *SessionsService) Get(ctx context.Context, c session.Caller) (api.SessionResponse, error) {
	r, err := s.current(ctx, c)
	if err != nil {
		return api.SessionResponse{}, err
	}
	return api.SessionResponse{User: r.User, Session: toSession(r, c.SID)}, nil
}

func (s *SessionsService) List(ctx context.Context, c session.Caller) (api.ListSessionsResponse, error) {
	if _, err := s.current(ctx, c); err != nil {
		return api.ListSessionsResponse{}, err
	}
	recs, err := s.store.List(ctx, c.User.ID)
	if err != nil {
		return api.ListSessionsResponse{}, unavailable(err)
	}
	hist, err := s.store.History(ctx, c.User.ID)
	if err != nil {
		return api.ListSessionsResponse{}, unavailable(err)
	}
	out := api.ListSessionsResponse{Sessions: []api.Session{}, History: []api.PastSession{}}
	for _, r := range recs {
		out.Sessions = append(out.Sessions, toSession(r, c.SID))
	}
	for _, h := range hist {
		out.History = append(out.History, api.PastSession{
			Device: h.Device, Browser: h.Browser, IP: h.IP, CreatedAt: h.CreatedAt, EndedAt: h.EndedAt, Reason: h.Reason,
		})
	}
	return out, nil
}

func (s *SessionsService) Revoke(ctx context.Context, c session.Caller, sid string) error {
	if _, err := s.current(ctx, c); err != nil {
		return err
	}
	r, found, err := s.store.Get(ctx, sid)
	if err != nil {
		return unavailable(err)
	}
	if !found || (r.UserID != c.User.ID && !c.User.Has(api.RoleAdmin)) {
		httpx.LoggerFrom(ctx).WarnContext(ctx, "revoke refused, session not found or not owned", slog.String("targetSid", sid), slog.Bool("found", found), slog.Int64("targetUserId", r.UserID))
		return errNoSession
	}
	reason := constants.ReasonRevoked
	if r.SID == c.SID {
		reason = constants.ReasonSignedOut
	}
	if err := s.store.Revoke(ctx, r, reason); err != nil {
		return unavailable(err)
	}
	httpx.LoggerFrom(ctx).InfoContext(ctx, "session revoked", slog.String("targetSid", sid), slog.Int64("targetUserId", r.UserID), slog.String("reason", reason), slog.Bool("byAdmin", r.UserID != c.User.ID))
	return nil
}

func (s *SessionsService) RevokeOthers(ctx context.Context, c session.Caller) (api.RevokeOthersResponse, error) {
	if _, err := s.current(ctx, c); err != nil {
		return api.RevokeOthersResponse{}, err
	}
	n, err := s.revokeOthers(ctx, c, constants.ReasonRevoked)
	if err == nil {
		httpx.LoggerFrom(ctx).InfoContext(ctx, "other sessions revoked", slog.Int("revoked", n))
	}
	return api.RevokeOthersResponse{Revoked: n}, err
}

func (s *SessionsService) revokeOthers(ctx context.Context, c session.Caller, reason string) (int, error) {
	recs, err := s.store.List(ctx, c.User.ID)
	if err != nil {
		return 0, unavailable(err)
	}
	n := 0
	for _, r := range recs {
		if r.SID == c.SID {
			continue
		}
		if err := s.store.Revoke(ctx, r, reason); err != nil {
			return n, unavailable(err)
		}
		n++
	}
	return n, nil
}

func (s *SessionsService) UpdateUser(ctx context.Context, u types.User) (int, error) {
	sids, err := s.store.UpdateUser(ctx, u)
	if err != nil {
		return len(sids), unavailable(err)
	}
	httpx.LoggerFrom(ctx).InfoContext(ctx, "live sessions updated", slog.Int64("targetUserId", u.ID), slog.Int("sessions", len(sids)))
	return len(sids), nil
}

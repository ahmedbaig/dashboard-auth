package controllers

import (
	"context"
	"net/http"

	"github.com/ahmedbaig/dashboard-auth/api"
	"github.com/ahmedbaig/dashboard-auth/internal/http/services"
	"github.com/ahmedbaig/dashboard-auth/internal/session"
	"github.com/ahmedbaig/go-backend-http"
)

func NewSessions(svc *services.SessionsService, users *services.UsersService) *Sessions {
	return &Sessions{svc: svc, users: users}
}

func (c *Sessions) Get(ctx context.Context, _ none) (api.SessionResponse, error) {
	caller, err := session.RequireCaller(ctx)
	if err != nil {
		return api.SessionResponse{}, err
	}
	return c.svc.Get(ctx, caller)
}

func (c *Sessions) List(ctx context.Context, _ none) (api.ListSessionsResponse, error) {
	caller, err := session.RequireCaller(ctx)
	if err != nil {
		return api.ListSessionsResponse{}, err
	}
	return c.svc.List(ctx, caller)
}

func (c *Sessions) Revoke(w http.ResponseWriter, r *http.Request) error {
	in, err := httpx.Bind[api.RevokeSessionRequest](r, httpx.NoBody())
	if err != nil {
		return err
	}
	caller, err := session.RequireCaller(r.Context())
	if err != nil {
		return err
	}
	if err := c.svc.Revoke(r.Context(), caller, in.SID); err != nil {
		return err
	}
	httpx.NoContent(w)
	return nil
}

func (c *Sessions) RevokeOthers(ctx context.Context, _ none) (api.RevokeOthersResponse, error) {
	caller, err := session.RequireCaller(ctx)
	if err != nil {
		return api.RevokeOthersResponse{}, err
	}
	return c.svc.RevokeOthers(ctx, caller)
}

func (c *Sessions) ChangePassword(w http.ResponseWriter, r *http.Request) error {
	in, err := httpx.Bind[api.ChangePasswordRequest](r)
	if err != nil {
		return err
	}
	caller, err := session.RequireCaller(r.Context())
	if err != nil {
		return err
	}
	if err := c.users.ChangePassword(r.Context(), caller, in); err != nil {
		return err
	}
	httpx.NoContent(w)
	return nil
}

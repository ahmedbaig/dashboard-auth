package controllers

import (
	"net/http"

	"github.com/ahmedbaig/dashboard-auth/api"
	"github.com/ahmedbaig/dashboard-auth/internal/http/services"
	"github.com/ahmedbaig/dashboard-auth/internal/session"
	"github.com/ahmedbaig/go-backend-http"
)

func NewAuth(svc *services.AuthService) *Auth { return &Auth{svc: svc} }

func (c *Auth) Login(w http.ResponseWriter, r *http.Request) error {
	in, err := httpx.Bind[api.LoginRequest](r)
	if err != nil {
		return err
	}
	out, err := c.svc.Login(r.Context(), in, session.ClientFrom(r))
	if err != nil {
		return err
	}
	httpx.OK(w, out)
	return nil
}

func (c *Auth) Refresh(w http.ResponseWriter, r *http.Request) error {
	in, err := httpx.Bind[api.RefreshRequest](r)
	if err != nil {
		return err
	}
	out, err := c.svc.Refresh(r.Context(), in.RefreshToken, session.ClientFrom(r))
	if err != nil {
		return err
	}
	httpx.OK(w, out)
	return nil
}

func (c *Auth) Logout(w http.ResponseWriter, r *http.Request) error {
	in, err := httpx.Bind[api.LogoutRequest](r, httpx.AllowUnknownFields())
	if err != nil && r.ContentLength > 0 {
		return err
	}
	var caller *session.Caller
	if cur, ok := session.CallerFrom(r.Context()); ok {
		caller = &cur
	}
	if err := c.svc.Logout(r.Context(), caller, in.RefreshToken); err != nil {
		return err
	}
	httpx.NoContent(w)
	return nil
}

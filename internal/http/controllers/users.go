package controllers

import (
	"context"
	"net/http"

	"github.com/ahmedbaig/dashboard-auth/api"
	"github.com/ahmedbaig/dashboard-auth/internal/http/services"
)

func NewUsers(svc *services.UsersService) *Users { return &Users{svc: svc} }

func (createdUser) StatusCode() int { return http.StatusCreated }

func (c *Users) Create(ctx context.Context, in api.CreateUserRequest) (createdUser, error) {
	out, err := c.svc.Create(ctx, in)
	return createdUser{out}, err
}

func (c *Users) SetAccess(ctx context.Context, in api.SetUserAccessRequest) (api.SetUserAccessResponse, error) {
	return c.svc.SetAccess(ctx, in)
}

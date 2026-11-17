package controllers

import (
	"github.com/ahmedbaig/dashboard-auth/api"
	"github.com/ahmedbaig/dashboard-auth/internal/http/services"
)

type Auth struct {
	svc *services.AuthService
}

type Sessions struct {
	svc   *services.SessionsService
	users *services.UsersService
}

type none struct{}

type Users struct {
	svc *services.UsersService
}

type createdUser struct{ api.UserResponse }

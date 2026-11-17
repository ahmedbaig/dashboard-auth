package api

import (
	"time"

	"github.com/ahmedbaig/go-backend-types"
	"github.com/ahmedbaig/go-backend-types/client"
)

type Tokens struct {
	AccessToken      string `json:"accessToken"`
	AccessExpiresIn  int64  `json:"accessExpiresIn"`
	RefreshToken     string `json:"refreshToken"`
	RefreshExpiresIn int64  `json:"refreshExpiresIn"`
}

type Session struct {
	SID        string    `json:"sid"`
	Device     string    `json:"device"`
	Browser    string    `json:"browser"`
	IP         string    `json:"ip"`
	CreatedAt  time.Time `json:"createdAt"`
	LastSeenAt time.Time `json:"lastSeenAt"`
	Current    bool      `json:"current"`
}

type PastSession struct {
	Device    string    `json:"device"`
	Browser   string    `json:"browser"`
	IP        string    `json:"ip"`
	CreatedAt time.Time `json:"createdAt"`
	EndedAt   time.Time `json:"endedAt"`
	Reason    string    `json:"reason"`
}

type LoginRequest struct {
	Email    string `json:"email" validate:"required,email,max=254"`
	Password string `json:"password" validate:"required,max=1024"`
}

type LoginResponse struct {
	User    types.User `json:"user"`
	Session Session    `json:"session"`
	Tokens  Tokens     `json:"tokens"`
}

type RefreshRequest struct {
	RefreshToken string `json:"refreshToken" validate:"required,max=512"`
}

type RefreshResponse struct {
	User   types.User `json:"user"`
	Tokens Tokens     `json:"tokens"`
}

type LogoutRequest struct {
	RefreshToken string `json:"refreshToken,omitempty" validate:"max=512"`
}

type SessionResponse struct {
	User    types.User `json:"user"`
	Session Session    `json:"session"`
}

type ListSessionsResponse struct {
	Sessions []Session     `json:"sessions"`
	History  []PastSession `json:"history"`
}

type RevokeSessionRequest struct {
	SID string `path:"sid" json:"-" validate:"required,max=64"`
}

type RevokeOthersResponse struct {
	Revoked int `json:"revoked"`
}

type ChangePasswordRequest struct {
	CurrentPassword string `json:"currentPassword" validate:"required,max=1024"`
	NewPassword     string `json:"newPassword" validate:"required,max=1024"`
}

type CreateUserRequest struct {
	Email    string   `json:"email" validate:"required,email,max=254"`
	Name     string   `json:"name" validate:"max=200"`
	Password string   `json:"password" validate:"required,max=1024"`
	Roles    []string `json:"roles" validate:"max=50,dive,min=1,max=64"`
	Features []string `json:"features" validate:"max=200,dive,min=1,max=64"`
}

type UserResponse struct {
	User types.User `json:"user"`
}

type SetUserAccessRequest struct {
	UserID   int64    `path:"userId" json:"-" validate:"required,min=1"`
	Roles    []string `json:"roles" validate:"max=50,dive,min=1,max=64"`
	Features []string `json:"features" validate:"max=200,dive,min=1,max=64"`
}

type SetUserAccessResponse struct {
	User            types.User `json:"user"`
	SessionsUpdated int        `json:"sessionsUpdated"`
}

type InfoResponse struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Environment string `json:"environment"`
	Status      string `json:"status"`
}

type Client struct {
	c *client.Client
}

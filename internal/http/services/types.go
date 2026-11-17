package services

import (
	"time"

	"github.com/ahmedbaig/dashboard-auth/internal/session"
	"github.com/ahmedbaig/dashboard-auth/internal/tokens"
	dash "github.com/ahmedbaig/dashboard-db-handler/types/dashboard"
	"github.com/ahmedbaig/go-backend-db"
	"github.com/ahmedbaig/go-backend-types"
)

type AuthOptions struct {
	AccessTTL    time.Duration
	RefreshGrace time.Duration
	Argon2       Argon2
	Now          func() time.Time
}

type AuthService struct {
	users   *UsersService
	store   *session.Store
	lockout *session.Lockout
	signer  *tokens.Signer
	o       AuthOptions
	dummy   string
	now     func() time.Time
}

type issued struct {
	Access     string    `json:"access"`
	AccessExp  time.Time `json:"accessExp"`
	Refresh    string    `json:"refresh"`
	RefreshExp time.Time `json:"refreshExp"`
}

type Argon2 struct {
	Memory  uint32
	Time    uint32
	Threads uint8
}

type SessionsService struct {
	store *session.Store
}

type Account struct {
	User     types.User
	Disabled bool
}

type UsersOptions struct {
	MinPasswordLength int
	Argon2            Argon2
}

type UsersService struct {
	c        *db.Client
	users    *db.Service[dash.User]
	creds    *db.Service[dash.PasswordCredential]
	roles    *db.Service[dash.UserRole]
	features *db.Service[dash.UserFeature]
	sessions *SessionsService
	o        UsersOptions
}

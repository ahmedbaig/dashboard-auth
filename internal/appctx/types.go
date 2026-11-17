package appctx

import (
	"log/slog"

	"github.com/ahmedbaig/dashboard-auth/internal/config"
	"github.com/ahmedbaig/dashboard-auth/internal/http/services"
	"github.com/ahmedbaig/dashboard-auth/internal/session"
	"github.com/ahmedbaig/dashboard-auth/internal/tokens"
	"github.com/ahmedbaig/go-backend-db"
	"github.com/ahmedbaig/go-backend-monitoring"
	"github.com/redis/go-redis/v9"
	"google.golang.org/grpc"
)

type Context struct {
	Config   config.Config
	Log      *slog.Logger
	Prober   *monitoring.Prober
	DB       *db.Client
	Redis    redis.UniversalClient
	Sessions *session.Store
	Keys     Keys
	Services Services

	dbConn  *grpc.ClientConn
	closers []func() error
}

type Option func(*Context)

type Keys struct {
	Signer *tokens.Signer
	Access *tokens.Verifier
	Edge   *tokens.Verifier
}

type Services struct {
	Auth     *services.AuthService
	Sessions *services.SessionsService
	Users    *services.UsersService
}

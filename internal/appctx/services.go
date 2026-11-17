package appctx

import (
	"github.com/ahmedbaig/dashboard-auth/internal/config"
	"github.com/ahmedbaig/dashboard-auth/internal/http/services"
	"github.com/ahmedbaig/dashboard-auth/internal/session"
	"github.com/ahmedbaig/dashboard-auth/internal/tokens"
	"github.com/ahmedbaig/go-backend-db"
	"github.com/redis/go-redis/v9"
)

func newServices(c config.Config, dbc *db.Client, rdb redis.UniversalClient, store *session.Store, signer *tokens.Signer) (Services, error) {
	a := c.App
	sessions := services.NewSessionsService(store)
	users := services.NewUsersService(dbc, sessions, services.UsersOptions{MinPasswordLength: a.MinPasswordLength})
	lockout := session.NewLockout(rdb, c.Shared.Redis.Prefix, a.Login.MaxFailures, a.Login.Lockout.Std())
	auth, err := services.NewAuthService(users, store, lockout, signer, services.AuthOptions{
		AccessTTL:    a.AccessTTL.Std(),
		RefreshGrace: a.RefreshGrace.Std(),
	})
	return Services{Auth: auth, Sessions: sessions, Users: users}, err
}

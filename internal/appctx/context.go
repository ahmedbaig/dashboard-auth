package appctx

import (
	"context"
	"errors"
	"log/slog"

	"github.com/ahmedbaig/dashboard-auth/internal/config"
	"github.com/ahmedbaig/dashboard-auth/internal/constants"
	"github.com/ahmedbaig/dashboard-auth/internal/session"
	"github.com/ahmedbaig/go-backend-db"
	"github.com/ahmedbaig/go-backend-monitoring"
	dbv1 "github.com/ahmedbaig/go-backend-proto/gen/go/ahmedbaig/dbhandler/v1"
	"github.com/ahmedbaig/go-backend-proto/grpcx"
)

func WithDB(c *db.Client) Option { return func(ctx *Context) { ctx.DB = c } }

func New(c config.Config, log *slog.Logger, opts ...Option) (*Context, error) {
	ctx := &Context{
		Config: c,
		Log:    log,
		Prober: monitoring.NewProber(constants.Name, monitoring.WithVersion(c.App.Version)),
	}
	for _, o := range opts {
		o(ctx)
	}
	if err := ctx.build(); err != nil {
		_ = ctx.Close(context.Background())
		return nil, err
	}
	return ctx, nil
}

func (c *Context) build() error {
	var err error
	if c.Keys, err = loadKeys(c.Config); err != nil {
		return err
	}
	if c.DB == nil {
		if c.DB, c.dbConn, err = connectDB(c.Config); err != nil {
			return err
		}
		c.closers = append(c.closers, c.dbConn.Close)
	}
	rdb, err := connectRedis(c.Config)
	if rdb != nil {
		c.Redis = rdb
		c.closers = append(c.closers, rdb.Close)
	}
	if err != nil {
		return err
	}
	a := c.Config.App
	c.Sessions = session.NewStore(c.Redis, session.Options{Prefix: c.Config.Shared.Redis.Prefix, TTL: a.RefreshTTL.Std(), HistorySize: a.HistorySize})
	c.Services, err = newServices(c.Config, c.DB, c.Redis, c.Sessions, c.Keys.Signer)
	return err
}

func (c *Context) RegisterProbes() error {
	if c.dbConn != nil {
		if err := c.Prober.AddProbe(constants.ProbeDBHandler, grpcx.HealthCheck(c.dbConn, dbv1.DBHandlerService_ServiceDesc.ServiceName)); err != nil {
			return err
		}
	}
	return c.Prober.AddProbe(constants.ProbeRedis, func(ctx context.Context) error { return c.Redis.Ping(ctx).Err() })
}

func (c *Context) Close(context.Context) error {
	var err error
	for i := len(c.closers) - 1; i >= 0; i-- {
		err = errors.Join(err, c.closers[i]())
	}
	c.closers = nil
	return err
}

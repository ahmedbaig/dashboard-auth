package server

import (
	"context"
	"log/slog"

	"github.com/ahmedbaig/dashboard-auth/internal/appctx"
	"github.com/ahmedbaig/dashboard-auth/internal/config"
	"github.com/ahmedbaig/dashboard-auth/internal/constants"
	authgrpc "github.com/ahmedbaig/dashboard-auth/internal/grpc"
	"github.com/ahmedbaig/dashboard-auth/internal/http/routes"
	"github.com/ahmedbaig/dashboard-auth/internal/jobs"
	"github.com/ahmedbaig/go-backend-http"
)

func Build(cfg config.Config, log *slog.Logger, opts ...appctx.Option) (*httpx.App, *authgrpc.Server, error) {
	actx, err := appctx.New(cfg, log, opts...)
	if err != nil {
		return nil, nil, err
	}
	if err := actx.RegisterProbes(); err != nil {
		_ = actx.Close(context.Background())
		return nil, nil, err
	}
	app := httpx.New(httpx.Options{
		Name:            constants.Name,
		Environment:     cfg.App.Environment,
		Logger:          log,
		Prober:          actx.Prober,
		RequestTimeout:  cfg.App.RequestTimeout.Std(),
		ShutdownTimeout: cfg.App.ShutdownTimeout.Std(),
		RateLimit:       &httpx.RateLimitOptions{},
	})
	routes.Register(app, actx)
	app.OnShutdown(actx.Close)

	runner := jobs.NewRunner(log, jobs.Capabilities(actx.DB, log, cfg.App.Jobs.CapabilitiesEvery.Std()))
	runner.Start(context.Background())
	app.OnShutdown(runner.Stop)

	srv := authgrpc.New(actx)
	if err := srv.Start(); err != nil {
		_ = runner.Stop(context.Background())
		_ = actx.Close(context.Background())
		return nil, nil, err
	}
	app.OnShutdown(srv.Shutdown)
	return app, srv, nil
}

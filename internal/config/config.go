package config

import (
	"net"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/ahmedbaig/dashboard-auth/internal/constants"
	cfg "github.com/ahmedbaig/go-backend-config"
	"github.com/ahmedbaig/go-backend-logging"
)

func (a App) Reflection() bool {
	return a.Environment == constants.EnvLocalhost || a.Environment == constants.EnvTesting
}

func Defaults() App {
	return App{
		Version:           "0.0.0",
		Host:              "127.0.0.1",
		Environment:       constants.EnvProduction,
		RequestTimeout:    cfg.Duration(30 * time.Second),
		ShutdownTimeout:   cfg.Duration(15 * time.Second),
		AccessTTL:         cfg.Duration(10 * time.Minute),
		RefreshTTL:        cfg.Duration(7 * 24 * time.Hour),
		RefreshGrace:      cfg.Duration(30 * time.Second),
		HistorySize:       20,
		MinPasswordLength: 12,
		Login:             Login{MaxFailures: 5, Lockout: cfg.Duration(15 * time.Minute)},
		DBHandler:         DBHandler{Host: "127.0.0.1", Timeout: cfg.Duration(30 * time.Second)},
		Jobs:              Jobs{CapabilitiesEvery: cfg.Duration(10 * time.Minute)},
	}
}

func SharedDefaults() Shared {
	return Shared{
		Auth:      Port{HTTP: 8081, GRPC: 9081},
		DBHandler: Port{HTTP: 8090, GRPC: 9090},
		Redis:     Redis{Addr: "localhost:6379", Prefix: "dashboard:"},
	}
}

func (c Config) GRPCAddr() string { return join(c.App.Host, c.Shared.Auth.GRPC) }

func (c Config) HTTPAddr() string { return join(c.App.Host, c.Shared.Auth.HTTP) }

func (c Config) DBHandlerAddr() string { return join(c.App.DBHandler.Host, c.Shared.DBHandler.GRPC) }

func join(host string, port int) string { return net.JoinHostPort(host, strconv.Itoa(port)) }

func Dir() string {
	if d := os.Getenv("CONFIG_DIR"); d != "" {
		return d
	}
	return "/app/var/secrets"
}

func Path(p string) string {
	if p == "" || filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(Dir(), p)
}

func Load() (Config, error) {
	app, err := cfg.Load(constants.Name, Defaults())
	if err != nil {
		return Config{}, err
	}
	shared, err := cfg.Load(constants.SharedName, SharedDefaults())
	if err != nil {
		return Config{}, err
	}
	log, err := cfg.Load(constants.Name+"-logger", logging.DefaultConfig())
	if err != nil {
		return Config{}, err
	}
	app.PrivateKey = Path(app.PrivateKey)
	shared.Keys.Auth = Path(shared.Keys.Auth)
	shared.Keys.Edge = Path(shared.Keys.Edge)
	return Config{App: app, Shared: shared, Logger: log}, nil
}

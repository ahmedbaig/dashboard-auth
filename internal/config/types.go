package config

import (
	cfg "github.com/ahmedbaig/go-backend-config"
	"github.com/ahmedbaig/go-backend-logging"
)

type Port struct {
	HTTP int `json:"http" validate:"min=0,max=65535"`
	GRPC int `json:"grpc" validate:"min=0,max=65535"`
}

type Redis struct {
	Addr     string `json:"addr" validate:"required"`
	Username string `json:"username"`
	Password string `json:"password"`
	DB       int    `json:"db" validate:"min=0"`
	TLS      bool   `json:"tls"`
	Prefix   string `json:"prefix"`
}

type Keys struct {
	Auth string `json:"auth" validate:"required"`
	Edge string `json:"edge" validate:"required"`
}

type Shared struct {
	Auth         Port   `json:"auth"`
	DBHandler    Port   `json:"dbHandler"`
	Redis        Redis  `json:"redis"`
	ServiceToken string `json:"serviceToken" validate:"required"`
	Keys         Keys   `json:"keys"`
}

type Login struct {
	MaxFailures int          `json:"maxFailures" validate:"min=1"`
	Lockout     cfg.Duration `json:"lockout"`
}

type DBHandler struct {
	Host     string       `json:"host"`
	Instance string       `json:"instance"`
	Timeout  cfg.Duration `json:"timeout"`
}

type Jobs struct {
	CapabilitiesEvery cfg.Duration `json:"capabilitiesEvery"`
}

type App struct {
	Version           string       `json:"version" validate:"required"`
	Host              string       `json:"host"`
	Environment       string       `json:"environment" validate:"oneof=localhost testing staging production"`
	RequestTimeout    cfg.Duration `json:"requestTimeout"`
	ShutdownTimeout   cfg.Duration `json:"shutdownTimeout"`
	PrivateKey        string       `json:"privateKey" validate:"required"`
	AccessTTL         cfg.Duration `json:"accessTtl"`
	RefreshTTL        cfg.Duration `json:"refreshTtl"`
	RefreshGrace      cfg.Duration `json:"refreshGrace"`
	HistorySize       int          `json:"historySize" validate:"min=0"`
	MinPasswordLength int          `json:"minPasswordLength" validate:"min=8"`
	Login             Login        `json:"login"`
	DBHandler         DBHandler    `json:"dbHandler"`
	Jobs              Jobs         `json:"jobs"`
	HTTPAPI           bool         `json:"httpApi"`
}

type Config struct {
	App    App
	Shared Shared
	Logger logging.Config
}

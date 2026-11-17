package constants

import "time"

const (
	Name       = "dashboard-auth"
	SharedName = "dashboard-services"
	IssuerAuth = "dashboard-auth"
	IssuerEdge = "dashboard-edge"
)

const (
	EnvLocalhost  = "localhost"
	EnvTesting    = "testing"
	EnvStaging    = "staging"
	EnvProduction = "production"
)

const (
	AudienceAccess      = "dashboard"
	AudienceInternal    = "dashboard-internal"
	BearerPrefix        = "Bearer "
	HeaderAuthorization = "Authorization"
)

const (
	MDUserToken    = "x-user-token"
	MDRefreshToken = "x-refresh-token"
	MDClientIP     = "x-client-ip"
	MDUserAgent    = "x-user-agent"
)

const (
	EventRevoked = "session.revoked"
	EventChanged = "session.changed"
	EventChannel = "auth.events"
)

const (
	ReasonSignedOut = "signed-out"
	ReasonRevoked   = "revoked"
	ReasonReuse     = "refresh-reuse"
	ReasonDisabled  = "disabled"
	ReasonPassword  = "password-changed"
)

const (
	KeySession     = "session:"
	KeyRevoked     = "revoked:"
	KeyUser        = "user:"
	KeyGrace       = "grace:"
	KeyLoginFail   = "login:fail:"
	KeyUserSession = ":sessions"
	KeyUserHistory = ":history"
)

const (
	ProbeDBHandler = "db-handler"
	ProbeRedis     = "redis"
)

const (
	Argon2SaltLen = 16
	Argon2KeyLen  = 32
)

const (
	RedisPingTimeout    = 5 * time.Second
	RotateRetries       = 5
	CapabilitiesJob     = "db-capabilities"
	CapabilitiesJitter  = 30 * time.Second
	CapabilitiesTimeout = 10 * time.Second
)

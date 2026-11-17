package api

const (
	PathLogin        = "/api/v1/auth/login"
	PathRefresh      = "/api/v1/auth/refresh"
	PathLogout       = "/api/v1/auth/logout"
	PathSession      = "/api/v1/session"
	PathSessions     = "/api/v1/auth/sessions"
	PathSessionByID  = "/api/v1/auth/sessions/{sid}"
	PathRevokeOthers = "/api/v1/auth/sessions/revoke-others"
	PathPassword     = "/api/v1/auth/password"
	PathUsers        = "/api/v1/auth/users"
	PathUserAccess   = "/api/v1/auth/users/{userId}/access"
	PathAdminInfo    = "/api/v1/admin/info"

	RoleAdmin = "admin"
)

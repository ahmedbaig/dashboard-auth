package session

import "errors"

var (
	ErrSessionGone = errors.New("session gone")
	ErrReuse       = errors.New("refresh token reuse")
)

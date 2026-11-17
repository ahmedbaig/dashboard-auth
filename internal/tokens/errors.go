package tokens

import "errors"

var (
	ErrExpired = errors.New("token expired")
	ErrInvalid = errors.New("token invalid")
)

package services

import (
	"errors"

	"github.com/ahmedbaig/go-backend-db"
	"github.com/ahmedbaig/go-backend-http"
)

var (
	errCredentials = httpx.E(httpx.CodeUnauthenticated).WithMessage("Email or password is wrong")
	errSignIn      = httpx.E(httpx.CodeUnauthenticated).WithMessage("Sign in again").WithCustomerActions("Sign in again")
	errDisabled    = httpx.E(httpx.CodeForbidden).WithMessage("This account is disabled")
	errNoSession   = httpx.E(httpx.CodeNotFound).WithMessage("Session not found")
)

func upstream(err error, notFound ...string) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, db.ErrNotFound):
		e := httpx.E(httpx.CodeNotFound)
		if len(notFound) > 0 {
			e = e.WithMessage(notFound[0])
		}
		return e.Wrap(err)
	case errors.Is(err, db.ErrConflict):
		return httpx.E(httpx.CodeConflict).Wrap(err)
	}
	return httpx.E(httpx.CodeBadGateway).Wrap(err)
}

func unavailable(err error) error {
	if err == nil {
		return nil
	}
	return httpx.E(httpx.CodeUnavailable).WithMessage("Sessions are unavailable").Wrap(err)
}

func isNotFound(err error) bool { return errors.Is(err, db.ErrNotFound) }

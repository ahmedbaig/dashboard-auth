package routes

import (
	"net/http"

	"github.com/ahmedbaig/dashboard-auth/api"
	"github.com/ahmedbaig/dashboard-auth/internal/appctx"
	"github.com/ahmedbaig/dashboard-auth/internal/constants"
	"github.com/ahmedbaig/go-backend-http"
)

func info(ctx *appctx.Context) func(http.ResponseWriter, *http.Request) error {
	return func(w http.ResponseWriter, r *http.Request) error {
		httpx.OK(w, api.InfoResponse{
			Name:        constants.Name,
			Version:     ctx.Config.App.Version,
			Environment: ctx.Config.App.Environment,
			Status:      string(ctx.Prober.Status()),
		})
		return nil
	}
}

package routes

import (
	"github.com/ahmedbaig/dashboard-auth/api"
	"github.com/ahmedbaig/dashboard-auth/internal/appctx"
	"github.com/ahmedbaig/dashboard-auth/internal/http/controllers"
	"github.com/ahmedbaig/dashboard-auth/internal/session"
	"github.com/ahmedbaig/go-backend-http"
)

func Register(app *httpx.App, ctx *appctx.Context) {
	authn := ctx.Sessions.Authenticate(ctx.Keys.Access)
	admin := app.Group("", authn, session.Require(), httpx.RequireRole(api.RoleAdmin))
	admin.Get(api.PathAdminInfo, httpx.HandlerFunc(info(ctx)))

	if !ctx.Config.App.HTTPAPI {
		return
	}
	svc := ctx.Services
	auth := controllers.NewAuth(svc.Auth)
	sess := controllers.NewSessions(svc.Sessions, svc.Users)
	users := controllers.NewUsers(svc.Users)

	public := app.Group("", authn)
	public.Post(api.PathLogin, httpx.HandlerFunc(auth.Login))
	public.Post(api.PathRefresh, httpx.HandlerFunc(auth.Refresh))
	public.Post(api.PathLogout, httpx.HandlerFunc(auth.Logout))

	signedIn := public.Group("", session.Require())
	signedIn.Get(api.PathSession, httpx.Handle(sess.Get, httpx.NoBody()))
	signedIn.Get(api.PathSessions, httpx.Handle(sess.List, httpx.NoBody()))
	signedIn.Delete(api.PathSessionByID, httpx.HandlerFunc(sess.Revoke))
	signedIn.Post(api.PathRevokeOthers, httpx.Handle(sess.RevokeOthers, httpx.NoBody()))
	signedIn.Put(api.PathPassword, httpx.HandlerFunc(sess.ChangePassword))

	adm := signedIn.Group("", httpx.RequireRole(api.RoleAdmin))
	adm.Post(api.PathUsers, httpx.Handle(users.Create))
	adm.Put(api.PathUserAccess, httpx.Handle(users.SetAccess))
}

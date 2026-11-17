package grpc

import (
	"context"

	"github.com/ahmedbaig/dashboard-auth/api"
	"github.com/ahmedbaig/dashboard-auth/internal/constants"
	"github.com/ahmedbaig/dashboard-auth/internal/http/services"
	"github.com/ahmedbaig/dashboard-auth/internal/session"
	authv1 "github.com/ahmedbaig/dashboard-auth/proto/gen/go/dashboard/auth/v1"
	"github.com/ahmedbaig/go-backend-http"
	"github.com/ahmedbaig/go-backend-types"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func NewAuth(auth *services.AuthService, sessions *services.SessionsService, users *services.UsersService) *Auth {
	return &Auth{auth: auth, sessions: sessions, users: users}
}

func caller(ctx context.Context) (session.Caller, error) {
	p, err := Require(ctx)
	if err != nil {
		return session.Caller{}, err
	}
	return session.Caller{User: p.User, SID: p.SID}, nil
}

func admin(ctx context.Context) error {
	_, err := RequireRole(ctx, api.RoleAdmin)
	return err
}

func client(ctx context.Context) session.Client {
	return session.Client{IP: Metadata(ctx, constants.MDClientIP), UserAgent: Metadata(ctx, constants.MDUserAgent)}
}

func valid[T any](v T) (T, error) { return v, httpx.Validate(v) }

func toUser(u types.User) *authv1.User {
	return &authv1.User{Id: u.ID, Email: u.Email, Name: u.Name, Roles: u.Roles, Features: u.Features}
}

func toSession(s api.Session) *authv1.Session {
	return &authv1.Session{
		Sid: s.SID, Device: s.Device, Browser: s.Browser, Ip: s.IP,
		CreatedAt: timestamppb.New(s.CreatedAt), LastSeenAt: timestamppb.New(s.LastSeenAt), Current: s.Current,
	}
}

func toTokens(t api.Tokens) *authv1.Tokens {
	return &authv1.Tokens{AccessToken: t.AccessToken, AccessExpiresIn: t.AccessExpiresIn, RefreshToken: t.RefreshToken, RefreshExpiresIn: t.RefreshExpiresIn}
}

func (h *Auth) Login(ctx context.Context, req *authv1.LoginRequest) (*authv1.LoginResponse, error) {
	in, err := valid(api.LoginRequest{Email: req.GetEmail(), Password: req.GetPassword()})
	if err != nil {
		return nil, err
	}
	out, err := h.auth.Login(ctx, in, client(ctx))
	if err != nil {
		return nil, err
	}
	return &authv1.LoginResponse{User: toUser(out.User), Session: toSession(out.Session), Tokens: toTokens(out.Tokens)}, nil
}

func (h *Auth) Refresh(ctx context.Context, req *authv1.RefreshRequest) (*authv1.RefreshResponse, error) {
	token := req.GetRefreshToken()
	if token == "" {
		token = Metadata(ctx, constants.MDRefreshToken)
	}
	out, err := h.auth.Refresh(ctx, token, client(ctx))
	if err != nil {
		return nil, err
	}
	return &authv1.RefreshResponse{User: toUser(out.User), Tokens: toTokens(out.Tokens)}, nil
}

func (h *Auth) Logout(ctx context.Context, _ *authv1.LogoutRequest) (*authv1.LogoutResponse, error) {
	var c *session.Caller
	if cur, err := caller(ctx); err == nil {
		c = &cur
	}
	return &authv1.LogoutResponse{}, h.auth.Logout(ctx, c, Metadata(ctx, constants.MDRefreshToken))
}

func (h *Auth) GetSession(ctx context.Context, _ *authv1.GetSessionRequest) (*authv1.GetSessionResponse, error) {
	c, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	out, err := h.sessions.Get(ctx, c)
	if err != nil {
		return nil, err
	}
	return &authv1.GetSessionResponse{User: toUser(out.User), Session: toSession(out.Session)}, nil
}

func (h *Auth) ListSessions(ctx context.Context, _ *authv1.ListSessionsRequest) (*authv1.ListSessionsResponse, error) {
	c, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	out, err := h.sessions.List(ctx, c)
	if err != nil {
		return nil, err
	}
	res := &authv1.ListSessionsResponse{}
	for _, s := range out.Sessions {
		res.Sessions = append(res.Sessions, toSession(s))
	}
	for _, p := range out.History {
		res.History = append(res.History, &authv1.PastSession{
			Device: p.Device, Browser: p.Browser, Ip: p.IP,
			CreatedAt: timestamppb.New(p.CreatedAt), EndedAt: timestamppb.New(p.EndedAt), Reason: p.Reason,
		})
	}
	return res, nil
}

func (h *Auth) RevokeSession(ctx context.Context, req *authv1.RevokeSessionRequest) (*authv1.RevokeSessionResponse, error) {
	c, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	in, err := valid(api.RevokeSessionRequest{SID: req.GetSid()})
	if err != nil {
		return nil, err
	}
	return &authv1.RevokeSessionResponse{}, h.sessions.Revoke(ctx, c, in.SID)
}

func (h *Auth) RevokeOtherSessions(ctx context.Context, _ *authv1.RevokeOtherSessionsRequest) (*authv1.RevokeOtherSessionsResponse, error) {
	c, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	out, err := h.sessions.RevokeOthers(ctx, c)
	return &authv1.RevokeOtherSessionsResponse{Revoked: int32(out.Revoked)}, err
}

func (h *Auth) ChangePassword(ctx context.Context, req *authv1.ChangePasswordRequest) (*authv1.ChangePasswordResponse, error) {
	c, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	in, err := valid(api.ChangePasswordRequest{CurrentPassword: req.GetCurrentPassword(), NewPassword: req.GetNewPassword()})
	if err != nil {
		return nil, err
	}
	return &authv1.ChangePasswordResponse{}, h.users.ChangePassword(ctx, c, in)
}

func (h *Auth) CreateUser(ctx context.Context, req *authv1.CreateUserRequest) (*authv1.CreateUserResponse, error) {
	if err := admin(ctx); err != nil {
		return nil, err
	}
	in, err := valid(api.CreateUserRequest{Email: req.GetEmail(), Name: req.GetName(), Password: req.GetPassword(), Roles: req.GetRoles(), Features: req.GetFeatures()})
	if err != nil {
		return nil, err
	}
	out, err := h.users.Create(ctx, in)
	if err != nil {
		return nil, err
	}
	return &authv1.CreateUserResponse{User: toUser(out.User)}, nil
}

func (h *Auth) SetUserAccess(ctx context.Context, req *authv1.SetUserAccessRequest) (*authv1.SetUserAccessResponse, error) {
	if err := admin(ctx); err != nil {
		return nil, err
	}
	in, err := valid(api.SetUserAccessRequest{UserID: req.GetUserId(), Roles: req.GetRoles(), Features: req.GetFeatures()})
	if err != nil {
		return nil, err
	}
	out, err := h.users.SetAccess(ctx, in)
	if err != nil {
		return nil, err
	}
	return &authv1.SetUserAccessResponse{User: toUser(out.User), SessionsUpdated: int32(out.SessionsUpdated)}, nil
}

package api

import (
	"context"

	"github.com/ahmedbaig/go-backend-types/client"
)

func NewClient(baseURL string, opts ...client.Option) *Client {
	return &Client{c: client.New(baseURL, opts...)}
}

func Bearer(accessToken string) client.Option {
	return client.WithHeader("Authorization", "Bearer "+accessToken)
}

func (c *Client) Login(ctx context.Context, req LoginRequest) (LoginResponse, error) {
	return client.Post[LoginResponse](ctx, c.c, PathLogin, req)
}

func (c *Client) Refresh(ctx context.Context, req RefreshRequest) (RefreshResponse, error) {
	return client.Post[RefreshResponse](ctx, c.c, PathRefresh, req)
}

func (c *Client) Logout(ctx context.Context, req LogoutRequest) error {
	_, err := client.Post[struct{}](ctx, c.c, PathLogout, req)
	return err
}

func (c *Client) Session(ctx context.Context) (SessionResponse, error) {
	return client.Get[SessionResponse](ctx, c.c, PathSession, nil)
}

func (c *Client) ListSessions(ctx context.Context) (ListSessionsResponse, error) {
	return client.Get[ListSessionsResponse](ctx, c.c, PathSessions, nil)
}

func (c *Client) RevokeSession(ctx context.Context, sid string) error {
	return client.Delete(ctx, c.c, client.Path(PathSessionByID, sid))
}

func (c *Client) RevokeOtherSessions(ctx context.Context) (RevokeOthersResponse, error) {
	return client.Post[RevokeOthersResponse](ctx, c.c, PathRevokeOthers, nil)
}

func (c *Client) ChangePassword(ctx context.Context, req ChangePasswordRequest) error {
	_, err := client.Put[struct{}](ctx, c.c, PathPassword, req)
	return err
}

func (c *Client) CreateUser(ctx context.Context, req CreateUserRequest) (UserResponse, error) {
	return client.Post[UserResponse](ctx, c.c, PathUsers, req)
}

func (c *Client) SetUserAccess(ctx context.Context, req SetUserAccessRequest) (SetUserAccessResponse, error) {
	return client.Put[SetUserAccessResponse](ctx, c.c, client.Path(PathUserAccess, req.UserID), req)
}

func (c *Client) AdminInfo(ctx context.Context) (InfoResponse, error) {
	return client.Get[InfoResponse](ctx, c.c, PathAdminInfo, nil)
}

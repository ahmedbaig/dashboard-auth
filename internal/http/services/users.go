package services

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/ahmedbaig/dashboard-auth/api"
	"github.com/ahmedbaig/dashboard-auth/internal/constants"
	"github.com/ahmedbaig/dashboard-auth/internal/session"
	dash "github.com/ahmedbaig/dashboard-db-handler/types/dashboard"
	"github.com/ahmedbaig/go-backend-db"
	"github.com/ahmedbaig/go-backend-http"
	"github.com/ahmedbaig/go-backend-types"
)

func NewUsersService(c *db.Client, sessions *SessionsService, o UsersOptions) *UsersService {
	if o.MinPasswordLength == 0 {
		o.MinPasswordLength = 12
	}
	if o.Argon2 == (Argon2{}) {
		o.Argon2 = DefaultArgon2
	}
	return &UsersService{
		c:        c,
		users:    dash.UserService(c),
		creds:    dash.PasswordCredentialService(c),
		roles:    dash.UserRoleService(c),
		features: dash.UserFeatureService(c),
		sessions: sessions,
		o:        o,
	}
}

var (
	uf = dash.UserFields
	cf = dash.PasswordCredentialFields
	rf = dash.UserRoleFields
	ff = dash.UserFeatureFields
)

func NormalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

func clean(values []string) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		if v = strings.TrimSpace(v); v != "" && !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	slices.Sort(out)
	return out
}

func (s *UsersService) account(ctx context.Context, u dash.User) (Account, error) {
	roles, err := s.roles.FindMany(ctx, db.Params{Where: db.W().Eq(rf.UserID, u.ID), Take: db.Take(200)})
	if err != nil {
		return Account{}, upstream(err)
	}
	features, err := s.features.FindMany(ctx, db.Params{Where: db.W().Eq(ff.UserID, u.ID), Take: db.Take(500)})
	if err != nil {
		return Account{}, upstream(err)
	}
	user := types.User{ID: u.ID, Email: u.Email, Name: u.Name}
	for _, r := range roles {
		user.Roles = append(user.Roles, r.Role)
	}
	for _, f := range features {
		user.Features = append(user.Features, f.Feature)
	}
	user.Roles, user.Features = clean(user.Roles), clean(user.Features)
	return Account{User: user, Disabled: u.Disabled}, nil
}

func (s *UsersService) find(ctx context.Context, where db.Where) (Account, error) {
	u, err := s.users.FindOne(ctx, where)
	if err != nil {
		return Account{}, upstream(err, "User not found")
	}
	return s.account(ctx, u)
}

func (s *UsersService) ByEmail(ctx context.Context, email string) (Account, error) {
	return s.find(ctx, db.W().Eq(uf.Email, NormalizeEmail(email)))
}

func (s *UsersService) ByID(ctx context.Context, id int64) (Account, error) {
	return s.find(ctx, db.W().Eq(uf.ID, id))
}

func (s *UsersService) PasswordHash(ctx context.Context, userID int64) (string, error) {
	c, err := s.creds.FindOne(ctx, db.W().Eq(cf.UserID, userID))
	return c.Hash, upstream(err, "User not found")
}

func (s *UsersService) setPasswordHash(ctx context.Context, userID int64, hash string) error {
	now := time.Now()
	_, err := s.creds.Upsert(ctx, []string{cf.UserID},
		dash.PasswordCredential{UserID: userID, Hash: hash, UpdatedAt: now},
		map[string]any{cf.Hash: hash, cf.UpdatedAt: now})
	return upstream(err)
}

func (s *UsersService) TouchLogin(ctx context.Context, userID int64) error {
	_, err := s.users.Update(ctx, db.W().Eq(uf.ID, userID), map[string]any{uf.LastLoginAt: time.Now()})
	return upstream(err)
}

func (s *UsersService) checkPassword(field, pw string) error {
	if len(pw) < s.o.MinPasswordLength {
		return httpx.E(httpx.CodeValidation).WithFields(httpx.FieldError{
			Field: field, Rule: "min", Message: fmt.Sprintf("Use at least %d characters", s.o.MinPasswordLength)})
	}
	return nil
}

func (s *UsersService) Create(ctx context.Context, in api.CreateUserRequest) (api.UserResponse, error) {
	email := NormalizeEmail(in.Email)
	if err := s.checkPassword("password", in.Password); err != nil {
		return api.UserResponse{}, err
	}
	if _, err := s.ByEmail(ctx, email); err == nil {
		httpx.LoggerFrom(ctx).InfoContext(ctx, "create user refused, email exists", slog.String("newEmail", email))
		return api.UserResponse{}, httpx.E(httpx.CodeConflict).WithMessage("A user with that email exists")
	} else if !isNotFound(err) {
		return api.UserResponse{}, err
	}
	hash, err := s.o.Argon2.Hash(in.Password)
	if err != nil {
		return api.UserResponse{}, err
	}
	now := time.Now()
	u, err := s.users.Create(ctx, dash.User{Email: email, Name: strings.TrimSpace(in.Name), CreatedAt: now, UpdatedAt: now})
	if err != nil {
		return api.UserResponse{}, upstream(err)
	}
	if err := s.setPasswordHash(ctx, u.ID, hash); err != nil {
		return api.UserResponse{}, err
	}
	user, err := s.replaceAccess(ctx, u.ID, in.Roles, in.Features)
	if err != nil {
		return api.UserResponse{}, err
	}
	httpx.LoggerFrom(ctx).InfoContext(ctx, "user created", slog.Int64("targetUserId", user.ID), slog.String("newEmail", user.Email), slog.Any("newRoles", user.Roles), slog.Any("newFeatures", user.Features))
	return api.UserResponse{User: user}, nil
}

func (s *UsersService) SetAccess(ctx context.Context, in api.SetUserAccessRequest) (api.SetUserAccessResponse, error) {
	if _, err := s.ByID(ctx, in.UserID); err != nil {
		return api.SetUserAccessResponse{}, err
	}
	user, err := s.replaceAccess(ctx, in.UserID, in.Roles, in.Features)
	if err != nil {
		return api.SetUserAccessResponse{}, err
	}
	httpx.LoggerFrom(ctx).InfoContext(ctx, "user access changed", slog.Int64("targetUserId", user.ID), slog.Any("newRoles", user.Roles), slog.Any("newFeatures", user.Features))
	n, err := s.sessions.UpdateUser(ctx, user)
	return api.SetUserAccessResponse{User: user, SessionsUpdated: n}, err
}

func (s *UsersService) ChangePassword(ctx context.Context, c session.Caller, in api.ChangePasswordRequest) error {
	if _, err := s.sessions.current(ctx, c); err != nil {
		return err
	}
	hash, err := s.PasswordHash(ctx, c.User.ID)
	if err != nil {
		return err
	}
	if ok, _ := VerifyPassword(hash, in.CurrentPassword); !ok {
		httpx.LoggerFrom(ctx).WarnContext(ctx, "password change refused, current password wrong")
		return httpx.E(httpx.CodeValidation).WithFields(httpx.FieldError{Field: "currentPassword", Rule: "match", Message: "Current password is wrong"})
	}
	if err := s.checkPassword("newPassword", in.NewPassword); err != nil {
		return err
	}
	nh, err := s.o.Argon2.Hash(in.NewPassword)
	if err != nil {
		return err
	}
	if err := s.setPasswordHash(ctx, c.User.ID, nh); err != nil {
		return err
	}
	n, err := s.sessions.revokeOthers(ctx, c, constants.ReasonPassword)
	if err != nil {
		return err
	}
	httpx.LoggerFrom(ctx).InfoContext(ctx, "password changed", slog.Int("sessionsSignedOut", n))
	return nil
}

func rows[T any](build func(string) T, values []string) (json.RawMessage, error) {
	out := make([]T, len(values))
	for i, v := range values {
		out[i] = build(v)
	}
	return json.Marshal(out)
}

func (s *UsersService) replaceAccess(ctx context.Context, userID int64, roles, features []string) (types.User, error) {
	queries := []db.Query{
		{Database: dash.Database, Service: dash.UserRoleTable, Method: db.DeleteMany, Params: db.Params{Where: db.W().Eq(rf.UserID, userID)}},
		{Database: dash.Database, Service: dash.UserFeatureTable, Method: db.DeleteMany, Params: db.Params{Where: db.W().Eq(ff.UserID, userID)}},
	}
	if rs := clean(roles); len(rs) > 0 {
		data, err := rows(func(r string) dash.UserRole { return dash.UserRole{UserID: userID, Role: r} }, rs)
		if err != nil {
			return types.User{}, err
		}
		queries = append(queries, db.Query{Database: dash.Database, Service: dash.UserRoleTable, Method: db.CreateMany, Params: db.Params{Data: data}})
	}
	if fs := clean(features); len(fs) > 0 {
		data, err := rows(func(f string) dash.UserFeature { return dash.UserFeature{UserID: userID, Feature: f} }, fs)
		if err != nil {
			return types.User{}, err
		}
		queries = append(queries, db.Query{Database: dash.Database, Service: dash.UserFeatureTable, Method: db.CreateMany, Params: db.Params{Data: data}})
	}
	if _, err := s.c.Transaction(ctx, db.Transaction{Database: dash.Database, Queries: queries}); err != nil {
		return types.User{}, upstream(err)
	}
	a, err := s.ByID(ctx, userID)
	return a.User, err
}

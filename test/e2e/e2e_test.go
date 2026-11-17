package e2e

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ahmedbaig/dashboard-auth/api"
	"github.com/ahmedbaig/dashboard-auth/internal/appctx"
	"github.com/ahmedbaig/dashboard-auth/internal/config"
	"github.com/ahmedbaig/dashboard-auth/internal/constants"
	"github.com/ahmedbaig/dashboard-auth/internal/http/services"
	"github.com/ahmedbaig/dashboard-auth/internal/server"
	"github.com/ahmedbaig/dashboard-auth/internal/testutil/fakedb"
	"github.com/ahmedbaig/dashboard-auth/internal/tokens"
	authv1 "github.com/ahmedbaig/dashboard-auth/proto/gen/go/dashboard/auth/v1"
	dash "github.com/ahmedbaig/dashboard-db-handler/types/dashboard"
	"github.com/ahmedbaig/go-backend-http"
	testkit "github.com/ahmedbaig/go-backend-testing"
	"github.com/ahmedbaig/go-backend-types"
	"github.com/alicebob/miniredis/v2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const password = "correct horse battery"

func writeKeys(t *testing.T, dir, name string) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(nil)
	p, _ := x509.MarshalPKCS8PrivateKey(priv)
	q, _ := x509.MarshalPKIXPublicKey(pub)
	for file, block := range map[string]*pem.Block{
		name + ".key": {Type: "PRIVATE KEY", Bytes: p},
		name + ".pub": {Type: "PUBLIC KEY", Bytes: q},
	} {
		if err := os.WriteFile(filepath.Join(dir, file), pem.EncodeToMemory(block), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

type env struct {
	http *testkit.Client
	grpc *grpc.ClientConn
	db   *fakedb.DB
	dir  string
}

func setup(t *testing.T, httpAPI bool) env {
	t.Helper()
	t.Setenv("CI", "true")
	dir := testkit.ConfigDir(t, map[string]any{
		"dashboard-services": map[string]any{
			"auth":         map[string]int{"http": 0, "grpc": 0},
			"redis":        map[string]string{"addr": miniredis.RunT(t).Addr(), "prefix": "test:"},
			"serviceToken": "svc-token",
			"keys":         map[string]string{"auth": "auth.pub", "edge": "edge.pub"},
		},
		"dashboard-auth":        map[string]any{"version": "test", "environment": "testing", "privateKey": "auth.key", "httpApi": httpAPI, "jobs": map[string]string{"capabilitiesEvery": "0s"}},
		"dashboard-auth-logger": map[string]any{"minimumLogLevel": "error", "logToConsole": false, "logToFile": false},
	})
	writeKeys(t, dir, "auth")
	writeKeys(t, dir, "edge")

	cfg, err := config.Load()
	testkit.NoError(t, err)
	log, _ := testkit.Logger(t)
	fdb := fakedb.New()
	app, srv, err := server.Build(cfg, log, appctx.WithDB(fdb.Client()))
	testkit.NoError(t, err)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})
	conn, err := grpc.NewClient(srv.Addr(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	testkit.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return env{http: testkit.NewClient(t, app.Handler()), grpc: conn, db: fdb, dir: dir}
}

func (e env) seed(t *testing.T, email string, roles ...string) types.User {
	t.Helper()
	ctx := context.Background()
	c := e.db.Client()
	u, err := dash.UserService(c).Create(ctx, dash.User{Email: email, Name: email})
	testkit.NoError(t, err)
	hash, err := services.Argon2{Memory: 64, Time: 1, Threads: 1}.Hash(password)
	testkit.NoError(t, err)
	_, err = dash.PasswordCredentialService(c).Create(ctx, dash.PasswordCredential{UserID: u.ID, Hash: hash})
	testkit.NoError(t, err)
	for _, r := range roles {
		_, err = dash.UserRoleService(c).Create(ctx, dash.UserRole{UserID: u.ID, Role: r})
		testkit.NoError(t, err)
	}
	return types.User{ID: u.ID, Email: email, Roles: roles}
}

func (e env) login(t *testing.T, email string) (*testkit.Client, api.LoginResponse) {
	t.Helper()
	res := testkit.Decode[api.LoginResponse](e.http.Post(api.PathLogin, api.LoginRequest{Email: email, Password: password}).Expect(200))
	return e.http.WithHeader("Authorization", "Bearer "+res.Tokens.AccessToken), res
}

func TestHealthAndMetrics(t *testing.T) {
	e := setup(t, false)
	e.http.Get("/healthz").Expect(200)
	e.http.Get("/metrics").Expect(200)
}

func TestHTTPSessionLifecycle(t *testing.T) {
	e := setup(t, true)
	e.seed(t, "ada@example.com")

	e.http.Get(api.PathSession).ExpectError(401, httpx.CodeUnauthenticated)
	e.http.Post(api.PathLogin, api.LoginRequest{Email: "ada@example.com", Password: "wrong password"}).ExpectError(401, httpx.CodeUnauthenticated)
	e.http.Post(api.PathLogin, map[string]string{"email": "nope"}).ExpectField("email", "email")

	ada, login := e.login(t, "ada@example.com")
	s := testkit.Decode[api.SessionResponse](ada.Get(api.PathSession).Expect(200))
	testkit.Equal(t, s.User.Email, "ada@example.com")
	testkit.True(t, s.Session.Current, "current session")

	list := testkit.Decode[api.ListSessionsResponse](ada.Get(api.PathSessions).Expect(200))
	testkit.Equal(t, len(list.Sessions), 1)

	r := testkit.Decode[api.RefreshResponse](e.http.Post(api.PathRefresh, api.RefreshRequest{RefreshToken: login.Tokens.RefreshToken}).Expect(200))
	testkit.True(t, r.Tokens.RefreshToken != login.Tokens.RefreshToken, "refresh rotates")

	ada.Post(api.PathLogout, nil).Expect(204)
	ada.Get(api.PathSession).ExpectError(401, httpx.CodeSessionExpired)
	e.http.Post(api.PathRefresh, api.RefreshRequest{RefreshToken: r.Tokens.RefreshToken}).ExpectError(401, httpx.CodeUnauthenticated)
}

func TestHTTPAdminCreatesUsers(t *testing.T) {
	e := setup(t, true)
	e.seed(t, "root@example.com", api.RoleAdmin)
	e.seed(t, "ada@example.com")
	root, _ := e.login(t, "root@example.com")
	ada, _ := e.login(t, "ada@example.com")

	req := api.CreateUserRequest{Email: "bob@example.com", Name: "Bob", Password: password, Features: []string{"weather:read"}}
	ada.Post(api.PathUsers, req).ExpectError(403, httpx.CodeForbidden)
	root.Post(api.PathUsers, api.CreateUserRequest{Email: "bad", Password: password}).ExpectField("email", "email")
	bob := testkit.Decode[api.UserResponse](root.Post(api.PathUsers, req).Expect(201)).User
	testkit.True(t, bob.Can("weather:read"), "features saved")
	root.Post(api.PathUsers, req).ExpectError(409, httpx.CodeConflict)

	bobClient, _ := e.login(t, "bob@example.com")
	path := strings.Replace(api.PathUserAccess, "{userId}", strconv.FormatInt(bob.ID, 10), 1)
	out := testkit.Decode[api.SetUserAccessResponse](root.Put(path, api.SetUserAccessRequest{Features: []string{"weather:read", "tv:watch"}}).Expect(200))
	testkit.Equal(t, out.SessionsUpdated, 1)
	s := testkit.Decode[api.SessionResponse](bobClient.Get(api.PathSession).Expect(200))
	testkit.True(t, s.User.Can("tv:watch"), "live session sees new access")

	info := testkit.Decode[api.InfoResponse](root.Get(api.PathAdminInfo).Expect(200))
	testkit.Equal(t, info.Name, constants.Name)
}

func TestHTTPAPICanBeTurnedOff(t *testing.T) {
	e := setup(t, false)
	e.http.Post(api.PathLogin, api.LoginRequest{Email: "a@example.com", Password: password}).ExpectError(404, httpx.CodeRouteNotFound)
}

func TestGRPCUsesTheSameServices(t *testing.T) {
	e := setup(t, false)
	admin := e.seed(t, "root@example.com", api.RoleAdmin)
	ada := e.seed(t, "ada@example.com")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	hr, err := healthpb.NewHealthClient(e.grpc).Check(ctx, &healthpb.HealthCheckRequest{Service: authv1.AuthService_ServiceDesc.ServiceName})
	testkit.NoError(t, err)
	testkit.Equal(t, hr.Status, healthpb.HealthCheckResponse_SERVING)

	client := authv1.NewAuthServiceClient(e.grpc)
	_, err = client.Login(ctx, &authv1.LoginRequest{Email: "ada@example.com", Password: password})
	testkit.Equal(t, status.Code(err), codes.Unauthenticated, "no service token")

	svc := metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer svc-token")
	login, err := client.Login(svc, &authv1.LoginRequest{Email: "ada@example.com", Password: password})
	testkit.NoError(t, err)
	testkit.True(t, login.GetTokens().GetRefreshToken() != "", "tokens issued")

	_, err = client.GetSession(svc, &authv1.GetSessionRequest{})
	testkit.Equal(t, status.Code(err), codes.Unauthenticated, "no user token")

	edgeKey, err := tokens.LoadPrivate(filepath.Join(e.dir, "edge.key"))
	testkit.NoError(t, err)
	edge := tokens.NewSigner(edgeKey, constants.IssuerEdge)
	adaToken, _ := edge.Internal(ada, login.GetSession().GetSid(), time.Minute)
	got, err := client.GetSession(metadata.AppendToOutgoingContext(svc, "x-user-token", adaToken), &authv1.GetSessionRequest{})
	testkit.NoError(t, err)
	testkit.Equal(t, got.GetUser().GetEmail(), "ada@example.com")

	_, err = client.CreateUser(metadata.AppendToOutgoingContext(svc, "x-user-token", adaToken), &authv1.CreateUserRequest{Email: "bob@example.com", Password: password})
	testkit.Equal(t, status.Code(err), codes.PermissionDenied, "non-admin create")

	adminToken, _ := edge.Internal(admin, "sid-admin", time.Minute)
	created, err := client.CreateUser(metadata.AppendToOutgoingContext(svc, "x-user-token", adminToken), &authv1.CreateUserRequest{Email: "bob@example.com", Password: password})
	testkit.NoError(t, err)
	testkit.Equal(t, created.GetUser().GetEmail(), "bob@example.com")
}

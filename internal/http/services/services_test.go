package services

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ahmedbaig/dashboard-auth/api"
	"github.com/ahmedbaig/dashboard-auth/internal/constants"
	"github.com/ahmedbaig/dashboard-auth/internal/session"
	"github.com/ahmedbaig/dashboard-auth/internal/testutil/fakedb"
	"github.com/ahmedbaig/dashboard-auth/internal/tokens"
	"github.com/ahmedbaig/go-backend-http"
	"github.com/ahmedbaig/go-backend-types"
	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

var fastArgon = Argon2{Memory: 64, Time: 1, Threads: 1}

const password = "correct horse battery"

type harness struct {
	t        *testing.T
	mr       *miniredis.Miniredis
	rdb      *redis.Client
	db       *fakedb.DB
	store    *session.Store
	auth     *AuthService
	sessions *SessionsService
	users    *UsersService
	clock    time.Time
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	h := &harness{t: t, mr: mr, rdb: rdb, db: fakedb.New(), clock: time.Now()}
	h.store = session.NewStore(rdb, session.Options{Prefix: "dashboard:", TTL: 7 * 24 * time.Hour, HistorySize: 10, Now: h.now})
	h.sessions = NewSessionsService(h.store)
	h.users = NewUsersService(h.db.Client(), h.sessions, UsersOptions{Argon2: fastArgon})
	priv, _ := tokens.Generate()
	auth, err := NewAuthService(h.users, h.store, session.NewLockout(rdb, "dashboard:", 5, 15*time.Minute), tokens.NewSigner(priv, "dashboard-auth"), AuthOptions{
		AccessTTL: 10 * time.Minute, RefreshGrace: 30 * time.Second, Argon2: fastArgon, Now: h.now,
	})
	if err != nil {
		t.Fatal(err)
	}
	h.auth = auth
	return h
}

func (h *harness) now() time.Time { return h.clock }

func (h *harness) advance(d time.Duration) {
	h.clock = h.clock.Add(d)
	h.mr.FastForward(d)
}

func (h *harness) user(email string, roles, features []string) types.User {
	h.t.Helper()
	res, err := h.users.Create(context.Background(), api.CreateUserRequest{Email: email, Name: email, Password: password, Roles: roles, Features: features})
	if err != nil {
		h.t.Fatal(err)
	}
	return res.User
}

func device(ua string) session.Client { return session.Client{IP: "192.0.2.10", UserAgent: ua} }

func (h *harness) login(email, ua string) api.LoginResponse {
	h.t.Helper()
	res, err := h.auth.Login(context.Background(), api.LoginRequest{Email: email, Password: password}, device(ua))
	if err != nil {
		h.t.Fatalf("login %s: %v", email, err)
	}
	return res
}

func as(res api.LoginResponse) session.Caller {
	return session.Caller{User: res.User, SID: res.Session.SID}
}

func (h *harness) refresh(token string) (api.RefreshResponse, error) {
	return h.auth.Refresh(context.Background(), token, device("Mozilla/5.0 (Macintosh; Intel Mac OS X 15_0) Safari/605.1"))
}

func code(err error) httpx.Code {
	if err == nil {
		return ""
	}
	return httpx.AsError(err).Code
}

func TestLoginIssuesTokensAndSession(t *testing.T) {
	h := newHarness(t)
	h.user("ada@example.com", nil, []string{"weather:read"})

	res := h.login("Ada@Example.com ", "Mozilla/5.0 (Macintosh; Intel Mac OS X 15_0) AppleWebKit Chrome/140 Safari/537")
	if res.Tokens.AccessExpiresIn != 600 || res.Tokens.RefreshExpiresIn != int64((7*24*time.Hour).Seconds()) {
		t.Fatalf("ttl seconds: %+v", res.Tokens)
	}
	if res.Session.Device != "Mac" || res.Session.Browser != "Chrome" {
		t.Fatalf("device: %+v", res.Session)
	}
	got, err := h.sessions.Get(context.Background(), as(res))
	if err != nil {
		t.Fatal(err)
	}
	if got.User.Email != "ada@example.com" || !got.Session.Current {
		t.Fatalf("session: %+v", got)
	}
}

func TestWrongPasswordAndUnknownEmailLookTheSame(t *testing.T) {
	h := newHarness(t)
	h.user("ada@example.com", nil, nil)

	_, wrong := h.auth.Login(context.Background(), api.LoginRequest{Email: "ada@example.com", Password: "nope nope nope"}, device(""))
	_, unknown := h.auth.Login(context.Background(), api.LoginRequest{Email: "bob@example.com", Password: "nope nope nope"}, device(""))
	if wrong == nil || unknown == nil || wrong.Error() != unknown.Error() {
		t.Fatalf("wrong=%v unknown=%v", wrong, unknown)
	}
}

func TestLockoutAfterFailures(t *testing.T) {
	h := newHarness(t)
	h.user("ada@example.com", nil, nil)
	for range 5 {
		_, _ = h.auth.Login(context.Background(), api.LoginRequest{Email: "ada@example.com", Password: "wrong password"}, device(""))
	}
	_, err := h.auth.Login(context.Background(), api.LoginRequest{Email: "ada@example.com", Password: password}, device(""))
	if code(err) != httpx.CodeRateLimited {
		t.Fatalf("want rate limited, got %v", err)
	}
	h.advance(16 * time.Minute)
	h.login("ada@example.com", "")
}

func TestRefreshRotatesWithGraceThenDetectsReuse(t *testing.T) {
	h := newHarness(t)
	h.user("ada@example.com", nil, nil)
	first := h.login("ada@example.com", "").Tokens.RefreshToken

	a, err := h.refresh(first)
	if err != nil {
		t.Fatal(err)
	}
	if a.Tokens.RefreshToken == first {
		t.Fatal("refresh token not rotated")
	}

	h.advance(10 * time.Second)
	b, err := h.refresh(first)
	if err != nil {
		t.Fatalf("second tab inside grace: %v", err)
	}
	if b.Tokens.RefreshToken != a.Tokens.RefreshToken || b.Tokens.AccessToken != a.Tokens.AccessToken {
		t.Fatal("grace should return the same pair")
	}

	h.advance(time.Minute)
	if _, err := h.refresh(first); code(err) != httpx.CodeUnauthenticated {
		t.Fatalf("reuse after grace should fail, got %v", err)
	}
	if _, err := h.refresh(a.Tokens.RefreshToken); code(err) != httpx.CodeUnauthenticated {
		t.Fatalf("reuse should kill the whole session, got %v", err)
	}
	sid, _, _ := session.SplitRefresh(first)
	if reason, ok, _ := h.store.Revoked(context.Background(), sid); !ok || reason != constants.ReasonReuse {
		t.Fatalf("tombstone: %q %v", reason, ok)
	}
}

func TestConcurrentRefreshFromTwoTabs(t *testing.T) {
	h := newHarness(t)
	h.user("ada@example.com", nil, nil)
	token := h.login("ada@example.com", "").Tokens.RefreshToken

	var wg sync.WaitGroup
	results := make([]api.RefreshResponse, 2)
	errs := make([]error, 2)
	for i := range 2 {
		wg.Go(func() { results[i], errs[i] = h.refresh(token) })
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if results[0].Tokens.RefreshToken != results[1].Tokens.RefreshToken {
		t.Fatal("both tabs should end up with the same refresh token")
	}
}

func TestLogoutTombstoneBlocksRefresh(t *testing.T) {
	h := newHarness(t)
	h.user("ada@example.com", nil, nil)
	res := h.login("ada@example.com", "")
	caller := as(res)

	h.advance(time.Hour)
	if err := h.auth.Logout(context.Background(), &caller, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := h.refresh(res.Tokens.RefreshToken); code(err) != httpx.CodeUnauthenticated {
		t.Fatalf("refresh after logout: %v", err)
	}
	ttl := h.mr.TTL("dashboard:revoked:" + res.Session.SID)
	if ttl <= 0 || ttl > 7*24*time.Hour-time.Hour+time.Second {
		t.Fatalf("tombstone ttl should be the refresh time left, got %v", ttl)
	}
	if _, err := h.sessions.Get(context.Background(), caller); code(err) != httpx.CodeUnauthenticated {
		t.Fatalf("session after logout: %v", err)
	}
}

func TestLogoutWithRefreshTokenOnly(t *testing.T) {
	h := newHarness(t)
	h.user("ada@example.com", nil, nil)
	res := h.login("ada@example.com", "")
	if err := h.auth.Logout(context.Background(), nil, res.Tokens.RefreshToken); err != nil {
		t.Fatal(err)
	}
	if _, err := h.refresh(res.Tokens.RefreshToken); code(err) != httpx.CodeUnauthenticated {
		t.Fatalf("refresh after logout: %v", err)
	}
}

func TestMissingSessionIsNeverRebuilt(t *testing.T) {
	h := newHarness(t)
	h.user("ada@example.com", nil, nil)
	res := h.login("ada@example.com", "")
	h.mr.Del("dashboard:session:" + res.Session.SID)

	if _, err := h.refresh(res.Tokens.RefreshToken); code(err) != httpx.CodeUnauthenticated {
		t.Fatalf("want sign in again, got %v", err)
	}
}

func TestDisabledUserLosesSessionOnRefresh(t *testing.T) {
	h := newHarness(t)
	u := h.user("ada@example.com", nil, nil)
	res := h.login("ada@example.com", "")
	h.db.Set("users", map[string]any{"id": u.ID}, map[string]any{"disabled": true})

	if _, err := h.refresh(res.Tokens.RefreshToken); code(err) != httpx.CodeForbidden {
		t.Fatalf("want forbidden, got %v", err)
	}
	if reason, ok, _ := h.store.Revoked(context.Background(), res.Session.SID); !ok || reason != constants.ReasonDisabled {
		t.Fatalf("tombstone: %q %v", reason, ok)
	}
}

func TestSetUserAccessUpdatesEverySessionAndPublishes(t *testing.T) {
	h := newHarness(t)
	u := h.user("ada@example.com", nil, []string{"weather:read", "tv:watch"})
	mac := h.login("ada@example.com", "Macintosh Chrome/140")
	phone := h.login("ada@example.com", "iPhone Safari/605")

	sub := h.rdb.Subscribe(context.Background(), h.store.Channel())
	defer sub.Close()
	if _, err := sub.Receive(context.Background()); err != nil {
		t.Fatal(err)
	}

	res, err := h.users.SetAccess(context.Background(), api.SetUserAccessRequest{UserID: u.ID, Features: []string{"weather:read"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.SessionsUpdated != 2 {
		t.Fatalf("updated %d", res.SessionsUpdated)
	}
	for _, s := range []api.LoginResponse{mac, phone} {
		got, err := h.sessions.Get(context.Background(), as(s))
		if err != nil {
			t.Fatal(err)
		}
		if f := got.User.Features; len(f) != 1 || f[0] != "weather:read" {
			t.Fatalf("features %v", f)
		}
	}
	msg, err := sub.ReceiveMessage(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(msg.Payload, `"type":"session.changed"`) {
		t.Fatalf("event %s", msg.Payload)
	}
}

func TestCreateUserRejectsDuplicatesAndShortPasswords(t *testing.T) {
	h := newHarness(t)
	h.user("ada@example.com", nil, nil)
	if _, err := h.users.Create(context.Background(), api.CreateUserRequest{Email: "ADA@example.com", Password: password}); code(err) != httpx.CodeConflict {
		t.Fatalf("duplicate: %v", err)
	}
	if _, err := h.users.Create(context.Background(), api.CreateUserRequest{Email: "bob@example.com", Password: "short"}); code(err) != httpx.CodeValidation {
		t.Fatalf("short password: %v", err)
	}
}

func TestRevokeOthersKeepsCurrent(t *testing.T) {
	h := newHarness(t)
	h.user("ada@example.com", nil, nil)
	keep := h.login("ada@example.com", "Macintosh Chrome/140")
	other := h.login("ada@example.com", "iPhone Safari/605")

	res, err := h.sessions.RevokeOthers(context.Background(), as(keep))
	if err != nil || res.Revoked != 1 {
		t.Fatalf("revoked %v %v", res, err)
	}
	if _, err := h.refresh(other.Tokens.RefreshToken); err == nil {
		t.Fatal("other session should be gone")
	}
	list, err := h.sessions.List(context.Background(), as(keep))
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Sessions) != 1 || !list.Sessions[0].Current || len(list.History) != 1 || list.History[0].Reason != constants.ReasonRevoked {
		t.Fatalf("list %+v", list)
	}
}

func TestRevokeSomeoneElsesSessionLooksMissing(t *testing.T) {
	h := newHarness(t)
	h.user("ada@example.com", nil, nil)
	h.user("bob@example.com", nil, nil)
	ada := h.login("ada@example.com", "")
	bob := h.login("bob@example.com", "")
	if err := h.sessions.Revoke(context.Background(), as(ada), bob.Session.SID); code(err) != httpx.CodeNotFound {
		t.Fatalf("want not found, got %v", err)
	}
}

func TestChangePasswordSignsOutOtherDevices(t *testing.T) {
	h := newHarness(t)
	h.user("ada@example.com", nil, nil)
	keep := h.login("ada@example.com", "Macintosh")
	other := h.login("ada@example.com", "iPhone")

	if err := h.users.ChangePassword(context.Background(), as(keep), api.ChangePasswordRequest{CurrentPassword: password, NewPassword: "short"}); code(err) != httpx.CodeValidation {
		t.Fatalf("short password: %v", err)
	}
	if err := h.users.ChangePassword(context.Background(), as(keep), api.ChangePasswordRequest{CurrentPassword: password, NewPassword: "a much longer password"}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.refresh(other.Tokens.RefreshToken); err == nil {
		t.Fatal("other device should be signed out")
	}
	if _, err := h.refresh(keep.Tokens.RefreshToken); err != nil {
		t.Fatalf("current device should stay: %v", err)
	}
}

func TestConcurrentUsersNeverSeeEachOther(t *testing.T) {
	h := newHarness(t)
	const n = 20
	for i := range n {
		h.user(fmt.Sprintf("user%d@example.com", i), nil, []string{"f" + strconv.Itoa(i)})
	}
	var wg sync.WaitGroup
	errs := make(chan error, n*5)
	for i := range n {
		for range 5 {
			wg.Go(func() {
				email := fmt.Sprintf("user%d@example.com", i)
				res, err := h.auth.Login(context.Background(), api.LoginRequest{Email: email, Password: password}, device(""))
				if err != nil {
					errs <- err
					return
				}
				got, err := h.sessions.Get(context.Background(), as(res))
				if err != nil {
					errs <- err
					return
				}
				if got.User.Email != email || got.User.Features[0] != "f"+strconv.Itoa(i) {
					errs <- fmt.Errorf("%s saw %s", email, got.User.Email)
				}
			})
		}
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

func TestPasswordHashRoundTrip(t *testing.T) {
	h, err := fastArgon.Hash("hunter2 hunter2")
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := VerifyPassword(h, "hunter2 hunter2"); err != nil || !ok {
		t.Fatalf("verify: %v %v", ok, err)
	}
	if ok, _ := VerifyPassword(h, "hunter3 hunter3"); ok {
		t.Fatal("wrong password accepted")
	}
	if _, err := VerifyPassword("$bcrypt$nope", "x"); err == nil {
		t.Fatal("foreign hash accepted")
	}
}

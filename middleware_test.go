package oidcauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func okHandler(t *testing.T, sawUser *User) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, ok := UserFromContext(r.Context())
		if !ok {
			t.Errorf("no user in context inside RequireAuth handler")
		}
		*sawUser = u
		w.WriteHeader(http.StatusOK)
	})
}

func authWithLoginPath() *Auth {
	a := cookieAuth(testCookieKey)
	a.loginPath = "/auth/login"
	return a
}

func TestRequireAuthRedirectsAnonymousGET(t *testing.T) {
	a := authWithLoginPath()
	var u User
	rr := httptest.NewRecorder()
	a.RequireAuth(okHandler(t, &u)).ServeHTTP(rr,
		httptest.NewRequest(http.MethodGet, "/private?tab=2", nil))

	if rr.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rr.Code)
	}
	loc, err := url.Parse(rr.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if loc.Path != "/auth/login" || loc.Query().Get("next") != "/private?tab=2" {
		t.Errorf("redirect = %q, want /auth/login?next=/private?tab=2", loc)
	}
}

func TestRequireAuthRejectsAnonymousPOST(t *testing.T) {
	a := authWithLoginPath()
	var u User
	rr := httptest.NewRecorder()
	a.RequireAuth(okHandler(t, &u)).ServeHTTP(rr,
		httptest.NewRequest(http.MethodPost, "/private", nil))
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rr.Code)
	}
}

func TestRequireAuthPassesValidSession(t *testing.T) {
	a := authWithLoginPath()
	want := User{Sub: "s1", Email: "e@example.com", Name: "N"}
	rr0 := httptest.NewRecorder()
	a.setSessionCookie(rr0, want)
	c := recordedCookie(t, rr0, a.sessionName())

	var got User
	req := httptest.NewRequest(http.MethodGet, "/private", nil)
	req.AddCookie(c)
	rr := httptest.NewRecorder()
	a.RequireAuth(okHandler(t, &got)).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("context user = %+v, want %+v", got, want)
	}
}

func TestRequireAuthRejectsExpiredSession(t *testing.T) {
	a := authWithLoginPath()
	rr0 := httptest.NewRecorder()
	a.setSessionCookie(rr0, User{Sub: "s1"})
	c := recordedCookie(t, rr0, a.sessionName())

	a.now = func() time.Time { return time.Now().Add(a.sessionLifetime + time.Minute) }
	var u User
	req := httptest.NewRequest(http.MethodGet, "/private", nil)
	req.AddCookie(c)
	rr := httptest.NewRecorder()
	a.RequireAuth(okHandler(t, &u)).ServeHTTP(rr, req)
	if rr.Code != http.StatusFound {
		t.Errorf("status = %d, want 302 redirect to login", rr.Code)
	}
}

func TestAuthenticateStoresAnonymousSentinel(t *testing.T) {
	a := authWithLoginPath()
	var sawUser User
	var sawOK, ran bool
	h := a.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ran = true
		sawUser, sawOK = UserFromContext(r.Context())
		// The sentinel is present even though nobody is logged in.
		_, present := r.Context().Value(ctxKey{}).(authResult)
		if !present {
			t.Errorf("no auth sentinel in context on an anonymous request")
		}
	}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	if !ran {
		t.Fatal("Authenticate rejected an anonymous request")
	}
	if sawOK || !reflect.DeepEqual(sawUser, User{}) {
		t.Errorf("UserFromContext = (%+v, %v), want (User{}, false)", sawUser, sawOK)
	}
}

func TestAuthenticatePassesUserOnPublicPage(t *testing.T) {
	a := authWithLoginPath()
	want := User{Sub: "s1"}
	rr0 := httptest.NewRecorder()
	a.setSessionCookie(rr0, want)
	c := recordedCookie(t, rr0, a.sessionName())

	var got User
	var ok bool
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(c)
	a.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, ok = UserFromContext(r.Context())
	})).ServeHTTP(httptest.NewRecorder(), req)
	if !ok || !reflect.DeepEqual(got, want) {
		t.Errorf("UserFromContext = (%+v, %v), want (%+v, true)", got, ok, want)
	}
}

func TestAuthenticateNoRenewPopulatesContext(t *testing.T) {
	a := authWithLoginPath()
	want := User{Sub: "s1"}
	rr0 := httptest.NewRecorder()
	a.setSessionCookie(rr0, want)
	c := recordedCookie(t, rr0, a.sessionName())

	var got User
	var ok bool
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(c)
	a.AuthenticateNoRenew(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, ok = UserFromContext(r.Context())
	})).ServeHTTP(httptest.NewRecorder(), req)
	if !ok || !reflect.DeepEqual(got, want) {
		t.Errorf("UserFromContext = (%+v, %v), want (%+v, true)", got, ok, want)
	}
}

// countingClock counts verifications indirectly: the middleware reads
// a.now() once per request it verifies, and nothing else on these code
// paths consults the clock. Renewal reuses that same reading rather
// than taking its own, so one verification == one clock read.
func countingClock(a *Auth, n *int) {
	now := a.now
	a.now = func() time.Time {
		*n++
		return now()
	}
}

func TestRequireAuthVerifiesExactlyOnce(t *testing.T) {
	mint := func() (*Auth, *http.Cookie) {
		a := authWithLoginPath()
		rr0 := httptest.NewRecorder()
		a.setSessionCookie(rr0, User{Sub: "s1"})
		return a, recordedCookie(t, rr0, a.sessionName())
	}
	run := func(t *testing.T, wrap bool) int {
		t.Helper()
		a, c := mint()
		var clockReads int
		countingClock(a, &clockReads)

		var got User
		h := a.RequireAuth(okHandler(t, &got))
		if wrap {
			h = a.Authenticate(h)
		}
		req := httptest.NewRequest(http.MethodGet, "/private", nil)
		req.AddCookie(c)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rr.Code)
		}
		if got.Sub != "s1" {
			t.Fatalf("context user = %+v, want sub s1", got)
		}
		return clockReads
	}

	// Pin both counts, not just their equality: comparing wrapped
	// against bare alone would pass vacuously if a later change made
	// the clock read once per request instead of once per verification.
	bare := run(t, false)
	if bare != 1 {
		t.Fatalf("clock reads bare = %d, want 1 (one verification)", bare)
	}
	if wrapped := run(t, true); wrapped != 1 {
		t.Errorf("clock reads wrapped = %d, want 1 (Authenticate verifies, RequireAuth reuses)",
			wrapped)
	}
}

// TestNestedAuthenticateVerifiesOnce pins that an inner
// AuthenticateNoRenew reuses the outer Authenticate's sentinel instead
// of verifying the cookie a second time.
func TestNestedAuthenticateVerifiesOnce(t *testing.T) {
	a := authWithLoginPath()
	rr0 := httptest.NewRecorder()
	a.setSessionCookie(rr0, User{Sub: "s1"})
	c := recordedCookie(t, rr0, a.sessionName())

	var clockReads int
	countingClock(a, &clockReads)

	var got User
	var ok bool
	h := a.Authenticate(a.AuthenticateNoRenew(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			got, ok = UserFromContext(r.Context())
		})))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(c)
	h.ServeHTTP(httptest.NewRecorder(), req)

	if !ok || got.Sub != "s1" {
		t.Fatalf("UserFromContext = (%+v, %v), want sub s1 and true", got, ok)
	}
	if clockReads != 1 {
		t.Errorf("clock reads = %d, want 1 (inner AuthenticateNoRenew reuses the sentinel)",
			clockReads)
	}
}

// TestRequireAuthRejectsWrappedInvalidSession covers the composed
// rejection path: the outer Authenticate finds no valid session and the
// inner RequireAuth must still reject from the sentinel.
func TestRequireAuthRejectsWrappedInvalidSession(t *testing.T) {
	t.Run("expired", func(t *testing.T) {
		a := authWithLoginPath()
		rr0 := httptest.NewRecorder()
		a.setSessionCookie(rr0, User{Sub: "s1"})
		c := recordedCookie(t, rr0, a.sessionName())
		a.now = func() time.Time { return time.Now().Add(a.sessionLifetime + time.Minute) }

		var u User
		req := httptest.NewRequest(http.MethodGet, "/private", nil)
		req.AddCookie(c)
		rr := httptest.NewRecorder()
		a.Authenticate(a.RequireAuth(okHandler(t, &u))).ServeHTTP(rr, req)
		if rr.Code != http.StatusFound {
			t.Errorf("status = %d, want 302 redirect to login", rr.Code)
		}
	})
	t.Run("tampered POST", func(t *testing.T) {
		a := authWithLoginPath()
		rr0 := httptest.NewRecorder()
		a.setSessionCookie(rr0, User{Sub: "s1"})
		c := recordedCookie(t, rr0, a.sessionName())
		c.Value += "x" // breaks the HMAC

		var u User
		req := httptest.NewRequest(http.MethodPost, "/private", nil)
		req.AddCookie(c)
		rr := httptest.NewRecorder()
		a.Authenticate(a.RequireAuth(okHandler(t, &u))).ServeHTTP(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401", rr.Code)
		}
	})
}

// TestRequireAuthIgnoresForeignSentinel proves the sentinel is
// instance-scoped: a session valid for Auth A must not authenticate a
// request through Auth B, which has a different cookie secret.
func TestRequireAuthIgnoresForeignSentinel(t *testing.T) {
	authA := authWithLoginPath()
	authB := cookieAuth("a-different-cookie-secret")
	authB.loginPath = "/auth/login"

	rr0 := httptest.NewRecorder()
	authA.setSessionCookie(rr0, User{Sub: "s1"})
	c := recordedCookie(t, rr0, authA.sessionName())

	var u User
	req := httptest.NewRequest(http.MethodGet, "/private", nil)
	req.AddCookie(c)
	rr := httptest.NewRecorder()
	// Auth A verifies and writes its sentinel; Auth B must re-verify
	// with its own secret and reject.
	authA.Authenticate(authB.RequireAuth(okHandler(t, &u))).ServeHTTP(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302: Auth B accepted Auth A's sentinel", rr.Code)
	}
}

// renewalFixture mints a session at base with a fresh Auth whose clock
// is settable, and returns the Auth, the minted cookie, and a function
// that moves the clock. The session lifetime is 1h and the max 24h (see
// cookieAuth), so the renew window opens at base+30m.
func renewalFixture(t *testing.T) (*Auth, *http.Cookie, func(time.Duration)) {
	t.Helper()
	a := authWithLoginPath()
	base := time.Date(2026, 8, 21, 0, 0, 0, 0, time.UTC)
	at := base
	a.now = func() time.Time { return at }

	rr := httptest.NewRecorder()
	a.setSessionCookie(rr, User{Sub: "s1"})
	c := recordedCookie(t, rr, a.sessionName())
	return a, c, func(d time.Duration) { at = base.Add(d) }
}

// decodeSession verifies and decodes a session cookie the middleware
// wrote, so assertions read the real signed payload.
func decodeSession(t *testing.T, a *Auth, c *http.Cookie) sessionPayload {
	t.Helper()
	payload, err := a.verify(purposeSession, c.Value)
	if err != nil {
		t.Fatalf("verify renewed cookie: %v", err)
	}
	var s sessionPayload
	if err := json.Unmarshal(payload, &s); err != nil {
		t.Fatalf("unmarshal renewed cookie: %v", err)
	}
	return s
}

// decodeSessionOrError is the goroutine-safe counterpart of
// decodeSession: it reports failures through an error instead of
// t.Fatalf, which must only run on the test's own goroutine.
func decodeSessionOrError(a *Auth, c *http.Cookie) (sessionPayload, error) {
	var s sessionPayload
	if c == nil {
		return s, errors.New("no session cookie set")
	}
	payload, err := a.verify(purposeSession, c.Value)
	if err != nil {
		return s, fmt.Errorf("verify renewed cookie: %w", err)
	}
	if err := json.Unmarshal(payload, &s); err != nil {
		return s, fmt.Errorf("unmarshal renewed cookie: %w", err)
	}
	return s, nil
}

func sessionCookieOrNil(rr *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range rr.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// serveAuthenticated runs h behind Authenticate with cookie c at the
// fixture's current clock, reporting whether the session was seen as
// valid.
func serveAuthenticated(a *Auth, c *http.Cookie, h http.Handler) (*httptest.ResponseRecorder, *bool) {
	sawUser := new(bool)
	req := httptest.NewRequest(http.MethodGet, "/page", nil)
	if c != nil {
		req.AddCookie(c)
	}
	rr := httptest.NewRecorder()
	a.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, ok := UserFromContext(r.Context())
		*sawUser = ok
		if h != nil {
			h.ServeHTTP(w, r)
		}
	})).ServeHTTP(rr, req)
	return rr, sawUser
}

func TestRenewalSkippedBeforeRenewWindow(t *testing.T) {
	a, c, advance := renewalFixture(t)
	advance(29 * time.Minute) // renew window opens at +30m

	rr, ok := serveAuthenticated(a, c, nil)
	if !*ok {
		t.Fatal("fresh session not accepted")
	}
	if got := sessionCookieOrNil(rr, a.sessionName()); got != nil {
		t.Errorf("Set-Cookie written outside the renew window: %q", got.Raw)
	}
}

func TestRenewalInRenewWindowPreservesIssuedAt(t *testing.T) {
	a, c, advance := renewalFixture(t)
	before := decodeSession(t, a, c)
	advance(31 * time.Minute)

	rr, ok := serveAuthenticated(a, c, nil)
	if !*ok {
		t.Fatal("session not accepted inside the renew window")
	}
	renewed := sessionCookieOrNil(rr, a.sessionName())
	if renewed == nil {
		t.Fatal("no Set-Cookie inside the renew window")
	}
	got := decodeSession(t, a, renewed)
	if got.IssuedAt != before.IssuedAt {
		t.Errorf("IssuedAt = %d, want %d (renewal must preserve it)", got.IssuedAt, before.IssuedAt)
	}
	wantExp := a.now().Add(a.sessionLifetime)
	if !got.Expiry.Equal(wantExp) {
		t.Errorf("renewed Expiry = %v, want %v", got.Expiry, wantExp)
	}
	if !got.Expiry.After(before.Expiry) {
		t.Errorf("renewed Expiry %v did not extend %v", got.Expiry, before.Expiry)
	}
	if got.User.Sub != "s1" {
		t.Errorf("renewed user = %+v, want sub s1", got.User)
	}
}

// TestRenewalWindowEqualToLifetimeRenewsEveryRequest pins the
// configuration WithSessionRenewWindow exists to make reachable: with
// the window equal to the lifetime, the trigger is true from the moment
// the cookie is written, so consecutive requests each re-issue it.
func TestRenewalWindowEqualToLifetimeRenewsEveryRequest(t *testing.T) {
	a, c, advance := renewalFixture(t)
	a.renewWindow = a.sessionLifetime

	advance(time.Minute)
	rr, ok := serveAuthenticated(a, c, nil)
	if !*ok {
		t.Fatal("session not accepted on the first request")
	}
	first := sessionCookieOrNil(rr, a.sessionName())
	if first == nil {
		t.Fatal("no Set-Cookie on the first request")
	}
	if got, want := decodeSession(t, a, first).Expiry, a.now().Add(a.sessionLifetime); !got.Equal(want) {
		t.Errorf("first renewed Expiry = %v, want %v", got, want)
	}

	advance(2 * time.Minute)
	rr, ok = serveAuthenticated(a, first, nil)
	if !*ok {
		t.Fatal("session not accepted on the second request")
	}
	second := sessionCookieOrNil(rr, a.sessionName())
	if second == nil {
		t.Fatal("no Set-Cookie on the second consecutive request")
	}
	if got, want := decodeSession(t, a, second).Expiry, a.now().Add(a.sessionLifetime); !got.Equal(want) {
		t.Errorf("second renewed Expiry = %v, want %v", got, want)
	}
}

func TestRenewalRejectedPastSessionLifetime(t *testing.T) {
	a, c, advance := renewalFixture(t)
	advance(time.Hour + time.Minute)

	rr, ok := serveAuthenticated(a, c, nil)
	if *ok {
		t.Error("session past the session lifetime was accepted")
	}
	if got := sessionCookieOrNil(rr, a.sessionName()); got != nil {
		t.Errorf("expired session renewed: %q", got.Raw)
	}
}

// TestRenewalRefusedPastMaxLifetime covers a session still inside its
// own lifetime whose max lifetime has passed. The max is keyed on the
// stored IssuedAt, so tightening it after mint applies retroactively --
// which is exactly how this state is reachable in production.
func TestRenewalRefusedPastMaxLifetime(t *testing.T) {
	a, c, advance := renewalFixture(t)
	a.maxSessionLifetime = 30 * time.Minute
	advance(45 * time.Minute) // past the max, still short of the +1h Expiry

	rr, ok := serveAuthenticated(a, c, nil)
	if *ok {
		t.Error("session past the max lifetime was accepted")
	}
	if got := sessionCookieOrNil(rr, a.sessionName()); got != nil {
		t.Errorf("session past the max lifetime was renewed: %q", got.Raw)
	}
}

// TestRenewedExpiryClampedToMaxLifetime pins the clamp: a renewal that
// would reach past IssuedAt+max advertises the max instead, so the cookie
// never claims a lifetime the server would refuse to honor.
func TestRenewedExpiryClampedToMaxLifetime(t *testing.T) {
	a, c, advance := renewalFixture(t)
	before := decodeSession(t, a, c)
	a.maxSessionLifetime = 75 * time.Minute
	advance(31 * time.Minute) // renewal would otherwise reach +91m

	rr, _ := serveAuthenticated(a, c, nil)
	renewed := sessionCookieOrNil(rr, a.sessionName())
	if renewed == nil {
		t.Fatal("no Set-Cookie inside the renew window")
	}
	got := decodeSession(t, a, renewed)
	wantExp := time.Unix(before.IssuedAt, 0).Add(a.maxSessionLifetime)
	if !got.Expiry.Equal(wantExp) {
		t.Errorf("clamped Expiry = %v, want %v", got.Expiry, wantExp)
	}
}

// TestNoRewriteOncePinnedAtMaxLifetime covers the request after the expiry has
// been clamped to the max lifetime deadline: the request is inside the renew
// window, so the trigger is still true, but the computed expiry is no longer
// later than the stored one and rewriting it would buy nothing.
func TestNoRewriteOncePinnedAtMaxLifetime(t *testing.T) {
	a, c, advance := renewalFixture(t)
	a.maxSessionLifetime = 75 * time.Minute
	advance(31 * time.Minute)

	rr, _ := serveAuthenticated(a, c, nil)
	pinned := sessionCookieOrNil(rr, a.sessionName())
	if pinned == nil {
		t.Fatal("no Set-Cookie inside the renew window")
	}

	advance(50 * time.Minute) // inside the renew window again, still short of the max
	rr2, ok := serveAuthenticated(a, pinned, nil)
	if !*ok {
		t.Fatal("session inside the max lifetime was rejected")
	}
	if got := sessionCookieOrNil(rr2, a.sessionName()); got != nil {
		t.Errorf("rewrote an identical cookie once pinned at the max lifetime: %q", got.Raw)
	}
}

// TestRenewalLandsWhenHandlerWritesBody is the reason renewal happens
// at middleware entry: a handler that writes a body flushes headers,
// so a cookie written after it would be lost.
func TestRenewalLandsWhenHandlerWritesBody(t *testing.T) {
	a, c, advance := renewalFixture(t)
	advance(31 * time.Minute)

	rr, ok := serveAuthenticated(a, c, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte("hello")); err != nil {
			t.Errorf("write body: %v", err)
		}
	}))
	if !*ok {
		t.Fatal("session not accepted inside the renew window")
	}
	if rr.Body.String() != "hello" {
		t.Errorf("body = %q, want %q", rr.Body.String(), "hello")
	}
	if sessionCookieOrNil(rr, a.sessionName()) == nil {
		t.Error("renewal Set-Cookie lost to a handler that wrote a body")
	}
}

// TestAuthenticateNoRenewNeverWritesCookie pins the split: the
// non-renewing mount verifies the same session but emits no credential.
func TestAuthenticateNoRenewNeverWritesCookie(t *testing.T) {
	a, c, advance := renewalFixture(t)
	advance(31 * time.Minute)

	req := httptest.NewRequest(http.MethodGet, "/page", nil)
	req.AddCookie(c)
	rr := httptest.NewRecorder()
	var ok bool
	a.AuthenticateNoRenew(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, ok = UserFromContext(r.Context())
	})).ServeHTTP(rr, req)

	if !ok {
		t.Fatal("session not accepted by AuthenticateNoRenew")
	}
	if got := sessionCookieOrNil(rr, a.sessionName()); got != nil {
		t.Errorf("AuthenticateNoRenew wrote a session cookie: %q", got.Raw)
	}
}

// TestRenewalWritesOneCookieWhenNested guards the sentinel
// short-circuit: an outer Authenticate owns the renewal, and an inner
// mount must not add a second Set-Cookie.
func TestRenewalWritesOneCookieWhenNested(t *testing.T) {
	a, c, advance := renewalFixture(t)
	advance(31 * time.Minute)

	req := httptest.NewRequest(http.MethodGet, "/page", nil)
	req.AddCookie(c)
	rr := httptest.NewRecorder()
	inner := a.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	a.Authenticate(inner).ServeHTTP(rr, req)

	n := 0
	for _, got := range rr.Result().Cookies() {
		if got.Name == a.sessionName() {
			n++
		}
	}
	if n != 1 {
		t.Errorf("session Set-Cookie count = %d, want 1", n)
	}
}

// sessionSetCookies returns the raw Set-Cookie header values that
// carry the session cookie, so a duplicate is visible even when the
// browser would have silently taken the last one.
func sessionSetCookies(rr *httptest.ResponseRecorder, name string) []string {
	var got []string
	for _, v := range rr.Result().Header["Set-Cookie"] {
		if setCookieName(v) == name {
			got = append(got, v)
		}
	}
	return got
}

// mintAgedSession mints a session that is already d old on a's clock,
// leaving the clock at base so anything else the request does (state
// cookie freshness, for one) sees the present.
func mintAgedSession(t *testing.T, a *Auth, base time.Time, d time.Duration) *http.Cookie {
	t.Helper()
	a.now = func() time.Time { return base.Add(-d) }
	rr := httptest.NewRecorder()
	a.setSessionCookie(rr, User{Sub: "s1"})
	c := recordedCookie(t, rr, a.sessionName())
	a.now = func() time.Time { return base }
	return c
}

// TestLogoutInRenewWindowEmitsOneCookie covers renewal racing a clear:
// Authenticate renews at entry, then the logout handler clears, and the
// response must carry exactly one session Set-Cookie, the clearing one.
func TestLogoutInRenewWindowEmitsOneCookie(t *testing.T) {
	idp := newFakeIDP(t)
	a := newTestAuth(t, idp, WithSessionLifetime(time.Hour), WithSessionRenewWindow(30*time.Minute), WithSessionMaxLifetime(24*time.Hour))
	base := time.Date(2026, 8, 21, 0, 0, 0, 0, time.UTC)
	c := mintAgedSession(t, a, base, 31*time.Minute) // renew window is 30m

	req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	req.AddCookie(c)
	rr := httptest.NewRecorder()
	a.Authenticate(a.LogoutHandler()).ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rr.Code)
	}
	got := sessionSetCookies(rr, a.sessionName())
	if len(got) != 1 {
		t.Fatalf("session Set-Cookie count = %d, want 1: %q", len(got), got)
	}
	only := sessionCookieOrNil(rr, a.sessionName())
	if only == nil || only.Value != "" || only.MaxAge >= 0 {
		t.Errorf("surviving cookie = %q, want the clearing one", got[0])
	}
}

// TestCallbackInRenewWindowEmitsOneCookie covers renewal racing a mint:
// a still-valid session inside its renew window logs in again, and the fresh
// session must be the response's only session Set-Cookie.
func TestCallbackInRenewWindowEmitsOneCookie(t *testing.T) {
	idp := newFakeIDP(t)
	a := newTestAuth(t, idp, WithSessionLifetime(time.Hour), WithSessionRenewWindow(30*time.Minute), WithSessionMaxLifetime(24*time.Hour))
	base := time.Date(2026, 8, 21, 0, 0, 0, 0, time.UTC)

	authURL, stateCookie := startLogin(t, a, "/auth/login")
	old := mintAgedSession(t, a, base, 31*time.Minute)

	idp.claims["nonce"] = authURL.Query().Get("nonce")
	cb := "/auth/callback?" + url.Values{
		"state": {authURL.Query().Get("state")},
		"code":  {"test-code"},
	}.Encode()
	req := httptest.NewRequest(http.MethodGet, cb, nil)
	req.AddCookie(stateCookie)
	req.AddCookie(old)
	rr := httptest.NewRecorder()
	a.Authenticate(a.CallbackHandler()).ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("callback status = %d, want 302: %s", rr.Code, rr.Body)
	}
	got := sessionSetCookies(rr, a.sessionName())
	if len(got) != 1 {
		t.Fatalf("session Set-Cookie count = %d, want 1: %q", len(got), got)
	}
	minted := sessionCookieOrNil(rr, a.sessionName())
	if minted == nil {
		t.Fatal("no session cookie on the callback response")
	}
	s := decodeSession(t, a, minted)
	if s.IssuedAt != base.Unix() {
		t.Errorf("IssuedAt = %d, want %d (the mint, not the renewal)", s.IssuedAt, base.Unix())
	}
}

// TestNoRenewOuterStillRenewsInner pins the mount-order fix: wrapping
// a renewing Authenticate in an AuthenticateNoRenew must not disable
// renewal for the inner routes. The strongest mount owns the renewal
// decision, not the outermost one.
func TestNoRenewOuterStillRenewsInner(t *testing.T) {
	a, c, advance := renewalFixture(t)
	before := decodeSession(t, a, c)
	advance(31 * time.Minute)

	req := httptest.NewRequest(http.MethodGet, "/page", nil)
	req.AddCookie(c)
	rr := httptest.NewRecorder()
	var ok bool
	inner := a.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, ok = UserFromContext(r.Context())
	}))
	a.AuthenticateNoRenew(inner).ServeHTTP(rr, req)

	if !ok {
		t.Fatal("session not accepted inside the renew window")
	}
	got := sessionSetCookies(rr, a.sessionName())
	if len(got) != 1 {
		t.Fatalf("session Set-Cookie count = %d, want 1: %q", len(got), got)
	}
	renewed := decodeSession(t, a, sessionCookieOrNil(rr, a.sessionName()))
	if renewed.IssuedAt != before.IssuedAt {
		t.Errorf("IssuedAt = %d, want %d (renewal must preserve it)", renewed.IssuedAt, before.IssuedAt)
	}
	if wantExp := a.now().Add(a.sessionLifetime); !renewed.Expiry.Equal(wantExp) {
		t.Errorf("renewed Expiry = %v, want %v", renewed.Expiry, wantExp)
	}
}

// TestRequireAuthOuterStillRenewsInner is the same fix on
// RequireAuth's inline verify path: its sentinel comes from a
// non-renewing verification, so an inner Authenticate must still renew.
func TestRequireAuthOuterStillRenewsInner(t *testing.T) {
	a, c, advance := renewalFixture(t)
	before := decodeSession(t, a, c)
	advance(31 * time.Minute)

	req := httptest.NewRequest(http.MethodGet, "/private", nil)
	req.AddCookie(c)
	rr := httptest.NewRecorder()
	var got User
	a.RequireAuth(a.Authenticate(okHandler(t, &got))).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	set := sessionSetCookies(rr, a.sessionName())
	if len(set) != 1 {
		t.Fatalf("session Set-Cookie count = %d, want 1: %q", len(set), set)
	}
	renewed := decodeSession(t, a, sessionCookieOrNil(rr, a.sessionName()))
	if renewed.IssuedAt != before.IssuedAt {
		t.Errorf("IssuedAt = %d, want %d (renewal must preserve it)", renewed.IssuedAt, before.IssuedAt)
	}
	if wantExp := a.now().Add(a.sessionLifetime); !renewed.Expiry.Equal(wantExp) {
		t.Errorf("renewed Expiry = %v, want %v", renewed.Expiry, wantExp)
	}
}

// TestNoRenewInsideRenewingStillOneCookie is the mirror of
// TestNoRenewOuterStillRenewsInner: the outer mount already renewed,
// so the inner non-renewing mount changes nothing and the response
// still carries exactly one session Set-Cookie.
func TestNoRenewInsideRenewingStillOneCookie(t *testing.T) {
	a, c, advance := renewalFixture(t)
	advance(31 * time.Minute)

	req := httptest.NewRequest(http.MethodGet, "/page", nil)
	req.AddCookie(c)
	rr := httptest.NewRecorder()
	inner := a.AuthenticateNoRenew(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	a.Authenticate(inner).ServeHTTP(rr, req)

	if got := sessionSetCookies(rr, a.sessionName()); len(got) != 1 {
		t.Errorf("session Set-Cookie count = %d, want 1: %q", len(got), got)
	}
}

// signedSession returns a session cookie value signed with a's secret
// from a hand-built payload, so a test can mint payloads the normal
// path never produces (no iat, a stale issue time).
func signedSession(a *Auth, payload []byte) *http.Cookie {
	return &http.Cookie{Name: a.sessionName(), Value: a.sign(purposeSession, payload)}
}

// concurrentBodyHandler writes a body so each request exercises the
// ordering renewal depends on: the Set-Cookie is written at middleware
// entry, before the handler touches the response.
func concurrentBodyHandler(t *testing.T, seenUser *bool) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, ok := UserFromContext(r.Context())
		*seenUser = ok
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("hello"))
	})
}

// TestConcurrentRequestsSameCookie drives many simultaneous requests
// carrying one cookie through one *Auth, across a renewing mount, a
// non-renewing mount, and a renewing mount nested inside a
// non-renewing one, and asserts every response individually rather
// than merely that nothing panicked.
//
// The renewal path is race-free by construction: it reads only
// immutable *Auth configuration (sessionLifetime, maxSessionLifetime,
// the cookie key ring, cookie name) plus a per-request clock reading,
// and writes only to that request's ResponseWriter. The authResult
// sentinel is a value copied into a per-request context, never shared.
// Corruption of shared state would therefore have to show up as a
// wrong per-response outcome, which is what the assertions below pin:
// exactly one session Set-Cookie where renewal is due, none where it
// is not, and a preserved IssuedAt on every renewed cookie.
func TestConcurrentRequestsSameCookie(t *testing.T) {
	a, c, advance := renewalFixture(t)
	before := decodeSession(t, a, c)
	advance(31 * time.Minute) // renew window opens at +30m: renewal is due
	wantExpiry := a.now().Add(a.sessionLifetime)

	mounts := []struct {
		name      string
		wrap      func(http.Handler) http.Handler
		wantRenew bool
	}{
		{"authenticate", a.Authenticate, true},
		{"no-renew", a.AuthenticateNoRenew, false},
		{"renew-nested-in-no-renew", func(h http.Handler) http.Handler {
			return a.AuthenticateNoRenew(a.Authenticate(h))
		}, true},
	}

	const perMount = 40
	// start is closed only after every goroutine is spawned, so they
	// all contend on the same cookie at once instead of trickling in
	// as the spawn loop runs.
	start := make(chan struct{})
	var wg sync.WaitGroup
	for _, m := range mounts {
		for range perMount {
			wg.Go(func() {
				<-start
				seenUser := new(bool)
				h := m.wrap(concurrentBodyHandler(t, seenUser))
				req := httptest.NewRequest(http.MethodGet, "/page", nil)
				req.AddCookie(c)
				rr := httptest.NewRecorder()
				h.ServeHTTP(rr, req)

				if rr.Code != http.StatusOK || rr.Body.String() != "hello" {
					t.Errorf("%s: status %d body %q, want 200 %q", m.name, rr.Code, rr.Body.String(), "hello")
				}
				if !*seenUser {
					t.Errorf("%s: valid session not seen by handler", m.name)
				}
				set := sessionSetCookies(rr, a.sessionName())
				if !m.wantRenew {
					if len(set) != 0 {
						t.Errorf("%s: %d session Set-Cookie, want 0", m.name, len(set))
					}
					return
				}
				if len(set) != 1 {
					t.Errorf("%s: %d session Set-Cookie, want exactly 1", m.name, len(set))
					return
				}
				got, err := decodeSessionOrError(a, sessionCookieOrNil(rr, a.sessionName()))
				if err != nil {
					t.Errorf("%s: %v", m.name, err)
					return
				}
				if got.IssuedAt != before.IssuedAt {
					t.Errorf("%s: IssuedAt = %d, want %d", m.name, got.IssuedAt, before.IssuedAt)
				}
				if !got.Expiry.Equal(wantExpiry) {
					t.Errorf("%s: renewed Expiry = %v, want %v", m.name, got.Expiry, wantExpiry)
				}
				if got.User.Sub != "s1" {
					t.Errorf("%s: renewed user = %+v, want sub s1", m.name, got.User)
				}
			})
		}
	}
	close(start)
	wg.Wait()
}

// TestNoRenewalWithoutValidSession pins the converse of the renewal
// rule: every way a session can fail to verify must also skip renewal. Where an
// expiry is verifiable at all (the cases whose payload decodes and is
// not deliberately in the past), it sits inside the renew window, so
// a cookie that verified would certainly be renewed.
// For the remaining cases (absent cookie, bad signature, garbage
// value, expired session) the control block at the end of the test is
// what rules out a clock explanation: it shows the same clock renewing
// a genuinely valid cookie.
func TestNoRenewalWithoutValidSession(t *testing.T) {
	a, valid, advance := renewalFixture(t)
	advance(31 * time.Minute)
	now := a.now()
	soon := now.Add(time.Minute) // inside the renew window: renewal would be due

	tampered := *valid
	tampered.Value = valid.Value[:len(valid.Value)-1] + "A"

	noIssuedAt, err := json.Marshal(struct {
		User   User      `json:"user"`
		Expiry time.Time `json:"exp"`
	}{User: User{Sub: "s1"}, Expiry: soon})
	if err != nil {
		t.Fatalf("marshal payload without iat: %v", err)
	}
	zeroIssuedAt, err := json.Marshal(sessionPayload{User: User{Sub: "s1"}, Expiry: soon, IssuedAt: 0})
	if err != nil {
		t.Fatalf("marshal payload with zero iat: %v", err)
	}
	expired, err := json.Marshal(sessionPayload{User: User{Sub: "s1"}, Expiry: now.Add(-time.Second), IssuedAt: now.Add(-time.Hour).Unix()})
	if err != nil {
		t.Fatalf("marshal expired payload: %v", err)
	}
	pastMax, err := json.Marshal(sessionPayload{User: User{Sub: "s1"}, Expiry: soon, IssuedAt: now.Add(-a.maxSessionLifetime - time.Second).Unix()})
	if err != nil {
		t.Fatalf("marshal past-max-lifetime payload: %v", err)
	}

	cases := []struct {
		name   string
		cookie *http.Cookie
	}{
		{"absent cookie", nil},
		{"bad signature", &tampered},
		{"garbage value", &http.Cookie{Name: a.sessionName(), Value: "not-a-signed-cookie"}},
		{"missing iat", signedSession(a, noIssuedAt)},
		{"zero iat", signedSession(a, zeroIssuedAt)},
		{"expired", signedSession(a, expired)},
		{"past max lifetime", signedSession(a, pastMax)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/page", nil)
			if tc.cookie != nil {
				req.AddCookie(tc.cookie)
			}
			rr := httptest.NewRecorder()
			sawUser := new(bool)
			a.Authenticate(concurrentBodyHandler(t, sawUser)).ServeHTTP(rr, req)
			if *sawUser {
				t.Error("invalid session accepted")
			}
			if set := sessionSetCookies(rr, a.sessionName()); len(set) != 0 {
				t.Errorf("renewal attempted on an invalid session: %q", set)
			}
		})
	}

	// Control: the same fixture and clock do renew a valid cookie, so
	// the assertions above are not passing for want of a renewal
	// trigger.
	rr, ok := serveAuthenticated(a, valid, nil)
	if !*ok {
		t.Fatal("control session not accepted")
	}
	if set := sessionSetCookies(rr, a.sessionName()); len(set) != 1 {
		t.Fatalf("control: %d session Set-Cookie, want 1", len(set))
	}
}

// validatorFixture is renewalFixture plus an app-supplied session
// validator, recording every call so a test can assert the validator
// never saw a request the library should have rejected on its own.
func validatorFixture(t *testing.T, fn func(ctx context.Context, u User, issuedAt time.Time) (bool, error)) (a *Auth, c *http.Cookie, advance func(time.Duration), calls *int) {
	t.Helper()
	a, c, advance = renewalFixture(t)
	calls = new(int)
	wrapped := func(ctx context.Context, u User, issuedAt time.Time) (bool, error) {
		*calls++
		return fn(ctx, u, issuedAt)
	}
	if err := WithSessionValidator(wrapped)(a); err != nil {
		t.Fatalf("WithSessionValidator: %v", err)
	}
	return a, c, advance, calls
}

// serveRequireAuth runs RequireAuth with cookie c, or with no cookie
// at all when c is nil.
func serveRequireAuth(a *Auth, c *http.Cookie) *httptest.ResponseRecorder {
	return serveRequireAuthMethod(a, c, http.MethodGet)
}

// serveRequireAuthMethod is serveRequireAuth with the request method
// chosen, for the cases where RequireAuth's GET/HEAD split matters.
func serveRequireAuthMethod(a *Auth, c *http.Cookie, method string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "/private", nil)
	if c != nil {
		req.AddCookie(c)
	}
	rr := httptest.NewRecorder()
	a.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rr, req)
	return rr
}

// TestSessionValidatorRejectsOldIssueTime is the revocation case the
// hook exists for: the app keeps a per-user epoch and refuses any
// session issued strictly before it. The rejection must be
// indistinguishable from an expired cookie, so the response is
// compared byte for byte against the same request made past the
// session lifetime.
func TestSessionValidatorRejectsOldIssueTime(t *testing.T) {
	var gotSub string
	a, c, advance, calls := validatorFixture(t, func(_ context.Context, u User, issuedAt time.Time) (bool, error) {
		gotSub = u.Sub
		// Epoch one minute after the cookie was minted.
		epoch := time.Date(2026, 8, 21, 0, 1, 0, 0, time.UTC)
		return !issuedAt.Before(epoch), nil
	})
	advance(5 * time.Minute)
	got := serveRequireAuth(a, c)
	if *calls != 1 {
		t.Errorf("validator calls = %d, want 1", *calls)
	}
	// The validator judges a real identity, not a zero value.
	if gotSub != "s1" {
		t.Errorf("validator saw Sub = %q, want %q", gotSub, "s1")
	}

	// Same request, same cookie, but past the session lifetime: the
	// rejection the client is allowed to distinguish from nothing.
	b, bc, badvance := renewalFixture(t)
	badvance(b.sessionLifetime + time.Minute)
	want := serveRequireAuth(b, bc)

	if got.Code != want.Code {
		t.Errorf("status = %d, want %d (expired-session status)", got.Code, want.Code)
	}
	if !reflect.DeepEqual(got.Result().Header, want.Result().Header) {
		t.Errorf("headers = %v, want %v (expired-session headers)", got.Result().Header, want.Result().Header)
	}
	if got.Body.String() != want.Body.String() {
		t.Errorf("body = %q, want %q (expired-session body)", got.Body, want.Body)
	}
}

// TestSessionValidatorSuppressesRenewal covers the other half of
// "rejected exactly as expired": a session the validator refuses must
// not be handed a fresh cookie, even though its clock puts it well
// inside the renew window.
func TestSessionValidatorSuppressesRenewal(t *testing.T) {
	a, c, advance, calls := validatorFixture(t, func(context.Context, User, time.Time) (bool, error) { return false, nil })
	advance(31 * time.Minute) // renew window opens at +30m

	rr, ok := serveAuthenticated(a, c, nil)
	if *ok {
		t.Error("rejected session seen as logged in")
	}
	if *calls != 1 {
		t.Errorf("validator calls = %d, want 1", *calls)
	}
	if got := sessionSetCookies(rr, a.sessionName()); len(got) != 0 {
		t.Errorf("renewed a session the validator rejected: %q", got)
	}
}

// TestSessionValidatorAcceptsAndRenews pins the ordinary production
// case: a configured validator that accepts leaves renewal alone, so
// an accepting hook costs a session nothing.
func TestSessionValidatorAcceptsAndRenews(t *testing.T) {
	a, c, advance, calls := validatorFixture(t, func(context.Context, User, time.Time) (bool, error) { return true, nil })
	advance(31 * time.Minute) // renew window opens at +30m

	rr, ok := serveAuthenticated(a, c, nil)
	if !*ok {
		t.Error("accepted session seen as logged out")
	}
	if *calls != 1 {
		t.Errorf("validator calls = %d, want 1", *calls)
	}
	if sessionCookieOrNil(rr, a.sessionName()) == nil {
		t.Error("no renewal with an accepting validator set")
	}
}

// TestSessionValidatorNotCalledOnUnverifiedCookie pins the contract
// that the validator only ever sees a User and issue time this package
// has already authenticated.
func TestSessionValidatorNotCalledOnUnverifiedCookie(t *testing.T) {
	valid := func(t *testing.T) (*Auth, *http.Cookie, *int) {
		t.Helper()
		a, c, _, calls := validatorFixture(t, func(context.Context, User, time.Time) (bool, error) { return true, nil })
		return a, c, calls
	}

	t.Run("no cookie", func(t *testing.T) {
		a, _, calls := valid(t)
		serveRequireAuth(a, nil)
		if *calls != 0 {
			t.Errorf("validator calls = %d, want 0", *calls)
		}
	})

	// A well-formed cookie signed by a key this Auth does not know:
	// it fails only at the signature comparison, so reaching the
	// validator would mean the hook runs ahead of the MAC check.
	t.Run("bad signature", func(t *testing.T) {
		a, _, calls := valid(t)
		foreign := cookieAuth(testForeignKey)
		foreign.now = a.now
		rr := httptest.NewRecorder()
		foreign.setSessionCookie(rr, User{Sub: "s1"})
		serveRequireAuth(a, recordedCookie(t, rr, foreign.sessionName()))
		if *calls != 0 {
			t.Errorf("validator calls = %d, want 0", *calls)
		}
	})
}

// TestSessionValidatorEpochBoundary pins the comparison the doc
// comment on WithSessionValidator prescribes. An epoch equal to a live
// session's IssuedAt leaves it alone -- which is why "log out
// everywhere" must set the epoch to now, not to the current cookie's
// issue time, since a stolen clone carries that same timestamp.
func TestSessionValidatorEpochBoundary(t *testing.T) {
	cases := []struct {
		name       string
		epochAfter time.Duration // epoch relative to the session's IssuedAt
		wantValid  bool
	}{
		{"epoch equals IssuedAt", 0, true},
		{"epoch is now", 5 * time.Minute, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var epoch time.Time
			a, c, advance, calls := validatorFixture(t, func(_ context.Context, _ User, issuedAt time.Time) (bool, error) {
				return !issuedAt.Before(epoch), nil
			})
			mintedAt := a.now()
			epoch = mintedAt.Add(tc.epochAfter)
			advance(5 * time.Minute) // the session is live either way

			_, ok := serveAuthenticated(a, c, nil)
			if *ok != tc.wantValid {
				t.Errorf("session valid = %v, want %v", *ok, tc.wantValid)
			}
			if *calls != 1 {
				t.Errorf("validator calls = %d, want 1", *calls)
			}
		})
	}
}

// TestSessionValidatorSubSecondEpoch pins the truncation the
// WithSessionValidator doc prescribes: an epoch set partway through a
// second must not revoke a session minted later in that same second,
// whose issuedAt truncates back to the top of it.
func TestSessionValidatorSubSecondEpoch(t *testing.T) {
	a := authWithLoginPath()
	base := time.Date(2026, 8, 21, 0, 0, 0, 0, time.UTC)
	epoch := base.Add(200 * time.Millisecond) // "log out everywhere" fires
	now := base.Add(900 * time.Millisecond)   // user logs back in
	a.now = func() time.Time { return now }

	calls := 0
	err := WithSessionValidator(func(_ context.Context, _ User, issuedAt time.Time) (bool, error) {
		calls++
		return !issuedAt.Before(epoch.Truncate(time.Second)), nil
	})(a)
	if err != nil {
		t.Fatalf("WithSessionValidator: %v", err)
	}

	rr := httptest.NewRecorder()
	a.setSessionCookie(rr, User{Sub: "s1"})
	c := recordedCookie(t, rr, a.sessionName())

	if _, ok := serveAuthenticated(a, c, nil); !*ok {
		t.Error("session minted after the epoch was revoked by it")
	}
	if calls != 1 {
		t.Errorf("validator calls = %d, want 1", calls)
	}
}

// TestSessionValidatorErrorRequireAuth pins the third outcome: a
// validator that cannot reach a verdict is an outage, not an
// authorization decision, so RequireAuth must answer 5xx rather than
// the login redirect an expired cookie earns.
func TestSessionValidatorErrorRequireAuth(t *testing.T) {
	a, c, advance, calls := validatorFixture(t, func(context.Context, User, time.Time) (bool, error) {
		return false, errors.New("revocation store down")
	})
	advance(5 * time.Minute)

	got := serveRequireAuth(a, c)
	if *calls != 1 {
		t.Errorf("validator calls = %d, want 1", *calls)
	}
	if got.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want %d", got.Code, http.StatusServiceUnavailable)
	}

	// The response an expired cookie gets, for contrast: the failure
	// must not be disguised as one.
	b, bc, badvance := renewalFixture(t)
	badvance(b.sessionLifetime + time.Minute)
	if expired := serveRequireAuth(b, bc); got.Code == expired.Code {
		t.Errorf("validator failure answered with the expired-session status %d", expired.Code)
	}
}

// TestSessionValidatorErrorAuthenticateIsAnonymous pins the other
// half: a public page must not go down because the app's revocation
// store did. The handler still runs, seeing an anonymous request.
func TestSessionValidatorErrorAuthenticateIsAnonymous(t *testing.T) {
	a, c, advance, calls := validatorFixture(t, func(context.Context, User, time.Time) (bool, error) {
		return false, errors.New("revocation store down")
	})
	advance(5 * time.Minute)

	ran := false
	rr, ok := serveAuthenticated(a, c, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ran = true
		w.WriteHeader(http.StatusOK)
	}))
	if !ran {
		t.Error("handler did not run")
	}
	if *ok {
		t.Error("request seen as logged in despite a failed validator")
	}
	if *calls != 1 {
		t.Errorf("validator calls = %d, want 1", *calls)
	}
	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}
}

// TestSessionValidatorErrorSuppressesRenewal: an unverifiable session
// is not renewed, so an outage cannot extend sessions it can no longer
// check.
func TestSessionValidatorErrorSuppressesRenewal(t *testing.T) {
	a, c, advance, _ := validatorFixture(t, func(context.Context, User, time.Time) (bool, error) {
		return true, errors.New("revocation store down")
	})
	advance(31 * time.Minute) // renew window opens at +30m

	rr, _ := serveAuthenticated(a, c, nil)
	if got := sessionSetCookies(rr, a.sessionName()); len(got) != 0 {
		t.Errorf("renewed a session the validator could not check: %q", got)
	}
}

// TestSessionValidatorReceivesRequestContext pins that the context
// handed to the validator is the request's own, so a validator doing
// I/O can honor cancellation and request-scoped values.
func TestSessionValidatorReceivesRequestContext(t *testing.T) {
	type reqKey struct{}

	var gotValue any
	var gotErr error
	a, c, _, calls := validatorFixture(t, func(ctx context.Context, _ User, _ time.Time) (bool, error) {
		gotValue = ctx.Value(reqKey{})
		gotErr = ctx.Err()
		return true, nil
	})

	ctx, cancel := context.WithCancel(context.WithValue(context.Background(), reqKey{}, "marker"))
	cancel() // cancellation is observable inside the validator
	req := httptest.NewRequest(http.MethodGet, "/page", nil).WithContext(ctx)
	req.AddCookie(c)
	a.Authenticate(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).
		ServeHTTP(httptest.NewRecorder(), req)

	if *calls != 1 {
		t.Fatalf("validator calls = %d, want 1", *calls)
	}
	if gotValue != "marker" {
		t.Errorf("ctx value = %v, want %q (not the request's context)", gotValue, "marker")
	}
	if !errors.Is(gotErr, context.Canceled) {
		t.Errorf("ctx.Err() = %v, want %v", gotErr, context.Canceled)
	}
}

// TestSessionValidatorErrorRequireAuthNonGET pins that the failure
// outcome is decided before RequireAuth's GET/HEAD split: a POST
// during an outage must get the same 503, not the 401 an
// unauthenticated POST earns.
func TestSessionValidatorErrorRequireAuthNonGET(t *testing.T) {
	a, c, advance, calls := validatorFixture(t, func(context.Context, User, time.Time) (bool, error) {
		return false, errors.New("revocation store down")
	})
	advance(5 * time.Minute)

	got := serveRequireAuthMethod(a, c, http.MethodPost)
	if *calls != 1 {
		t.Errorf("validator calls = %d, want 1", *calls)
	}
	if got.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want %d", got.Code, http.StatusServiceUnavailable)
	}
}

// TestSessionValidatorErrorComposedMiddleware is the realistic
// production mounting: Authenticate wraps the whole tree and
// RequireAuth guards a route inside it. The failure has to survive the
// verify-once context handoff, or the inner RequireAuth falls back to
// the login redirect this outcome exists to prevent.
func TestSessionValidatorErrorComposedMiddleware(t *testing.T) {
	a, c, advance, calls := validatorFixture(t, func(context.Context, User, time.Time) (bool, error) {
		return false, errors.New("revocation store down")
	})
	advance(5 * time.Minute)

	req := httptest.NewRequest(http.MethodGet, "/private", nil)
	req.AddCookie(c)
	rr := httptest.NewRecorder()
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	a.Authenticate(a.RequireAuth(h)).ServeHTTP(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusServiceUnavailable)
	}
	// The cookie is verified once however the middlewares nest, so the
	// app's validator is consulted once too.
	if *calls != 1 {
		t.Errorf("validator calls = %d, want 1", *calls)
	}
}

// TestSessionUnavailableFromContext pins the accessor an app with its
// own gate needs: it must separate an outage from the two states that
// legitimately look anonymous, since only the outage must not redirect
// to login.
func TestSessionUnavailableFromContext(t *testing.T) {
	cases := []struct {
		name       string
		validator  func(context.Context, User, time.Time) (bool, error)
		withCookie bool
		want       bool
	}{
		{"validator failed", func(context.Context, User, time.Time) (bool, error) {
			return false, errors.New("revocation store down")
		}, true, true},
		{"validator rejected", func(context.Context, User, time.Time) (bool, error) {
			return false, nil
		}, true, false},
		{"valid session", func(context.Context, User, time.Time) (bool, error) {
			return true, nil
		}, true, false},
		{"anonymous", func(context.Context, User, time.Time) (bool, error) {
			return true, nil
		}, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, c, advance, _ := validatorFixture(t, tc.validator)
			advance(5 * time.Minute)
			if !tc.withCookie {
				c = nil
			}

			var got bool
			ran := false
			serveAuthenticated(a, c, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				ran = true
				got = SessionUnavailableFromContext(r.Context())
			}))
			if !ran {
				t.Fatal("handler did not run")
			}
			if got != tc.want {
				t.Errorf("SessionUnavailableFromContext = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestSessionUnavailableFromContextWithoutMiddleware: with no sentinel
// on the context there is nothing to report, and the app falls through
// to its ordinary anonymous handling.
func TestSessionUnavailableFromContextWithoutMiddleware(t *testing.T) {
	if SessionUnavailableFromContext(context.Background()) {
		t.Error("reported unavailable with no middleware on the context")
	}
}

// logCapture is a minimal slog.Handler that keeps every record so a
// test can assert the level something was logged at. It is safe for
// concurrent use because a handler installed on an Auth may be reached
// from more than one request goroutine.
type logCapture struct {
	mu      sync.Mutex
	records []slog.Record
}

func (h *logCapture) Enabled(context.Context, slog.Level) bool { return true }

func (h *logCapture) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = append(h.records, r.Clone())
	return nil
}

func (h *logCapture) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *logCapture) WithGroup(string) slog.Handler      { return h }

// matching returns the level and message of every captured record
// whose message contains substr.
func (h *logCapture) matching(substr string) []slog.Record {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []slog.Record
	for _, r := range h.records {
		if strings.Contains(r.Message, substr) {
			out = append(out, r)
		}
	}
	return out
}

// captureLogs points a's logger at a fresh capture, replacing the
// discarding logger the fixtures install.
func captureLogs(t *testing.T, a *Auth) *logCapture {
	t.Helper()
	h := &logCapture{}
	if err := WithLogger(slog.New(h))(a); err != nil {
		t.Fatalf("WithLogger: %v", err)
	}
	return h
}

// wantValidatorLog asserts that exactly one session-validator record
// was logged, at level want.
func wantValidatorLog(t *testing.T, h *logCapture, want slog.Level) {
	t.Helper()
	got := h.matching("session validator")
	if len(got) != 1 {
		t.Fatalf("session validator records = %d, want 1: %v", len(got), got)
	}
	if got[0].Level != want {
		t.Errorf("logged %q at %v, want %v", got[0].Message, got[0].Level, want)
	}
}

// TestValidatorFailureLogsWarn: an ordinary validator error is an
// outage in a dependency the operator needs to see, so it is warn.
func TestValidatorFailureLogsWarn(t *testing.T) {
	a, c, advance, _ := validatorFixture(t, func(context.Context, User, time.Time) (bool, error) {
		return false, errors.New("revocation store unreachable")
	})
	h := captureLogs(t, a)
	advance(5 * time.Minute)

	if got := serveRequireAuth(a, c); got.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", got.Code)
	}
	wantValidatorLog(t, h, slog.LevelWarn)
}

// TestValidatorCanceledLogsDebug: the doc tells validators to honor
// cancellation, so a correct one reports the context error on every
// aborted or timed-out request. That is ordinary traffic, and a client
// could amplify it on purpose, so it drops to debug -- with the same
// 503. Both context errors are wrapped, to pin errors.Is rather than
// equality.
func TestValidatorCanceledLogsDebug(t *testing.T) {
	for name, cause := range map[string]error{
		"canceled":          context.Canceled,
		"deadline exceeded": context.DeadlineExceeded,
	} {
		t.Run(name, func(t *testing.T) {
			a, c, advance, _ := validatorFixture(t, func(context.Context, User, time.Time) (bool, error) {
				return false, fmt.Errorf("lookup: %w", cause)
			})
			h := captureLogs(t, a)
			advance(5 * time.Minute)

			if got := serveRequireAuth(a, c); got.Code != http.StatusServiceUnavailable {
				t.Fatalf("status = %d, want 503", got.Code)
			}
			wantValidatorLog(t, h, slog.LevelDebug)
		})
	}
}

// TestValidatorFailureOnCanceledRequestLogsDebug: the client is
// already gone, so whatever error the validator reports is a
// consequence of that, not an outage.
func TestValidatorFailureOnCanceledRequestLogsDebug(t *testing.T) {
	a, c, advance, calls := validatorFixture(t, func(context.Context, User, time.Time) (bool, error) {
		return false, errors.New("read tcp: use of closed network connection")
	})
	h := captureLogs(t, a)
	advance(5 * time.Minute)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := httptest.NewRequest(http.MethodGet, "/private", nil).WithContext(ctx)
	req.AddCookie(c)
	rr := httptest.NewRecorder()
	a.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rr, req)

	if *calls != 1 {
		t.Fatalf("validator calls = %d, want 1", *calls)
	}
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rr.Code)
	}
	wantValidatorLog(t, h, slog.LevelDebug)
}

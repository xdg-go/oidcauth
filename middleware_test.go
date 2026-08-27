package oidcauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
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
	req.AddCookie(c)
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

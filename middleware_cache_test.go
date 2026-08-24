package oidcauth

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"
	"time"
)

// wantCacheHeaders asserts the exact Cache-Control value and that
// Vary carries exactly the entries given, so a stray extra Vary or a
// downgraded Cache-Control fails.
func wantCacheHeaders(t *testing.T, rr *httptest.ResponseRecorder, cacheControl string, vary []string) {
	t.Helper()
	if got := rr.Header().Get("Cache-Control"); got != cacheControl {
		t.Errorf("Cache-Control = %q, want %q", got, cacheControl)
	}
	got := rr.Header().Values("Vary")
	if !reflect.DeepEqual(got, vary) {
		t.Errorf("Vary = %q, want %q", got, vary)
	}
}

func TestRenewedResponseIsUncacheable(t *testing.T) {
	a, c, advance := renewalFixture(t)
	advance(31 * time.Minute) // renew window opens at +30m

	rr, ok := serveAuthenticated(a, c, nil)
	if !*ok {
		t.Fatal("session not accepted")
	}
	if sessionCookieOrNil(rr, a.sessionCookieName) == nil {
		t.Fatal("no renewal Set-Cookie, so this test proves nothing")
	}
	wantCacheHeaders(t, rr, "private, no-store", []string{"Cookie"})
}

func TestValidSessionWithoutRenewalIsPrivate(t *testing.T) {
	a, c, advance := renewalFixture(t)
	advance(29 * time.Minute) // outside the renew window: no renewal

	rr, ok := serveAuthenticated(a, c, nil)
	if !*ok {
		t.Fatal("session not accepted")
	}
	if got := sessionCookieOrNil(rr, a.sessionCookieName); got != nil {
		t.Fatalf("unexpected renewal Set-Cookie: %q", got.Raw)
	}
	wantCacheHeaders(t, rr, "private", []string{"Cookie"})
}

// TestNoRenewValidSessionIsPrivate covers the same rule on the mount
// that never writes a cookie: "private" is the strongest it can reach.
func TestNoRenewValidSessionIsPrivate(t *testing.T) {
	a, c, advance := renewalFixture(t)
	advance(31 * time.Minute) // inside the renew window, but this mount will not renew

	req := httptest.NewRequest(http.MethodGet, "/page", nil)
	req.AddCookie(c)
	rr := httptest.NewRecorder()
	a.AuthenticateNoRenew(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := UserFromContext(r.Context()); !ok {
			t.Error("session not accepted")
		}
	})).ServeHTTP(rr, req)

	wantCacheHeaders(t, rr, "private", []string{"Cookie"})
}

// TestAnonymousKeepsHandlerCacheControl is the reason the header is
// written only for a verified session: a public page must stay
// shared-cacheable.
func TestAnonymousKeepsHandlerCacheControl(t *testing.T) {
	a := authWithLoginPath()
	req := httptest.NewRequest(http.MethodGet, "/public", nil)
	rr := httptest.NewRecorder()
	a.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := UserFromContext(r.Context()); ok {
			t.Error("anonymous request reported a user")
		}
		w.Header().Set("Cache-Control", "public")
	})).ServeHTTP(rr, req)

	wantCacheHeaders(t, rr, "public", []string{"Cookie"})
}

// TestAnonymousGetsNoCacheControl is the stricter half of the same
// rule: with a handler that sets no Cache-Control at all, the header
// must be absent entirely. This is what fails if markPrivateResponse
// is ever called unconditionally.
func TestAnonymousGetsNoCacheControl(t *testing.T) {
	a := authWithLoginPath()
	req := httptest.NewRequest(http.MethodGet, "/public", nil)
	rr := httptest.NewRecorder()
	a.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := UserFromContext(r.Context()); ok {
			t.Error("anonymous request reported a user")
		}
	})).ServeHTTP(rr, req)

	if got := rr.Header()["Cache-Control"]; len(got) != 0 {
		t.Errorf("Cache-Control = %q, want no header at all", got)
	}
	wantCacheHeaders(t, rr, "", []string{"Cookie"})
}

// TestBareRequireAuthSetsCacheHeaders pins the inline-verify path:
// with no Authenticate mount, RequireAuth is the only middleware that
// runs and must write the headers itself.
func TestBareRequireAuthSetsCacheHeaders(t *testing.T) {
	a, c, advance := renewalFixture(t)
	advance(31 * time.Minute)

	req := httptest.NewRequest(http.MethodGet, "/private", nil)
	req.AddCookie(c)
	rr := httptest.NewRecorder()
	var u User
	a.RequireAuth(okHandler(t, &u)).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	// RequireAuth never renews, so "private" is correct here even
	// though the session is inside its renew window.
	wantCacheHeaders(t, rr, "private", []string{"Cookie"})
}

// TestRequireAuthInsideAuthenticateAddsVaryOnce pins the count under
// nesting: only the mount that actually verifies adds Vary: Cookie, so
// however deep the mounts stack, a response carries it once. Every
// response through the middleware still gets it, per docs/decisions.md
// ("Send Vary: Cookie unconditionally") -- unconditional means not
// gated on whether a session is present, not once per mount.
func TestRequireAuthInsideAuthenticateAddsVaryOnce(t *testing.T) {
	a, c, advance := renewalFixture(t)
	advance(29 * time.Minute)

	req := httptest.NewRequest(http.MethodGet, "/private", nil)
	req.AddCookie(c)
	rr := httptest.NewRecorder()
	var u User
	a.Authenticate(a.RequireAuth(okHandler(t, &u))).ServeHTTP(rr, req)

	wantCacheHeaders(t, rr, "private", []string{"Cookie"})
}

// TestNestedAuthenticateUpgradesToNoStore pins the sentinel-hit
// renewal path: the outer non-renewing mount writes "private", then
// the inner renewing mount renews on the same request and upgrades it
// to "private, no-store".
func TestNestedAuthenticateUpgradesToNoStore(t *testing.T) {
	a, c, advance := renewalFixture(t)
	advance(31 * time.Minute) // inside the renew window: the inner mount renews

	req := httptest.NewRequest(http.MethodGet, "/page", nil)
	req.AddCookie(c)
	rr := httptest.NewRecorder()
	a.AuthenticateNoRenew(a.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := UserFromContext(r.Context()); !ok {
			t.Error("session not accepted")
		}
	}))).ServeHTTP(rr, req)

	if sessionCookieOrNil(rr, a.sessionCookieName) == nil {
		t.Fatal("no renewal Set-Cookie, so this test proves nothing")
	}
	wantCacheHeaders(t, rr, "private, no-store", []string{"Cookie"})
}

// TestHandlerVaryEntriesSurvive pins Header().Add over Set.
func TestHandlerVaryEntriesSurvive(t *testing.T) {
	a := authWithLoginPath()
	req := httptest.NewRequest(http.MethodGet, "/public", nil)
	rr := httptest.NewRecorder()
	a.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Vary", "Accept-Encoding")
	})).ServeHTTP(rr, req)

	wantCacheHeaders(t, rr, "", []string{"Cookie", "Accept-Encoding"})
}

func TestLogoutResponseIsUncacheable(t *testing.T) {
	a := authWithLoginPath()
	req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	rr := httptest.NewRecorder()
	a.LogoutHandler().ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rr.Code)
	}
	// No middleware ran, so Vary is not expected here: the cookie
	// write is what makes this response uncacheable.
	wantCacheHeaders(t, rr, "private, no-store", nil)
}

func TestClearSessionResponseIsUncacheable(t *testing.T) {
	a := authWithLoginPath()
	rr := httptest.NewRecorder()
	a.ClearSession(rr)
	wantCacheHeaders(t, rr, "private, no-store", nil)
}

func TestCallbackResponseIsUncacheable(t *testing.T) {
	idp := newFakeIDP(t)
	a := newTestAuth(t, idp)

	authURL, stateCookie := startLogin(t, a, "/auth/login")
	idp.claims["nonce"] = authURL.Query().Get("nonce")
	cb := "/auth/callback?" + url.Values{
		"state": {authURL.Query().Get("state")},
		"code":  {"test-code"},
	}.Encode()
	req := httptest.NewRequest(http.MethodGet, cb, nil)
	req.AddCookie(stateCookie)
	rr := httptest.NewRecorder()
	a.Authenticate(a.CallbackHandler()).ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("callback status = %d, want 302: %s", rr.Code, rr.Body)
	}
	wantCacheHeaders(t, rr, "private, no-store", []string{"Cookie"})
}

// TestLoginRedirectIsUncacheable covers the login redirect: it carries
// the signed state cookie, so a shared cache must not store and replay
// that 302.
func TestLoginRedirectIsUncacheable(t *testing.T) {
	idp := newFakeIDP(t)
	a := newTestAuth(t, idp)

	req := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
	rr := httptest.NewRecorder()
	a.LoginHandler().ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("login status = %d, want 302: %s", rr.Code, rr.Body)
	}
	if sessionCookieOrNil(rr, a.stateCookieName()) == nil {
		t.Fatal("no state Set-Cookie, so this test proves nothing")
	}
	wantCacheHeaders(t, rr, "private, no-store", nil)
}

// TestNoRenewInsideRenewingKeepsNoStore pins the reverse nesting:
// the outer renewing mount writes the cookie and "private, no-store",
// then the inner non-renewing mount hits the sentinel and must not
// downgrade the header back to "private".
// TestNoRenewInsideRenewingStillOneCookie covers the same nesting but
// only counts Set-Cookie, so it cannot see the downgrade.
func TestNoRenewInsideRenewingKeepsNoStore(t *testing.T) {
	a, c, advance := renewalFixture(t)
	advance(31 * time.Minute) // inside the renew window: the outer mount renews

	req := httptest.NewRequest(http.MethodGet, "/page", nil)
	req.AddCookie(c)
	rr := httptest.NewRecorder()
	a.Authenticate(a.AuthenticateNoRenew(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := UserFromContext(r.Context()); !ok {
			t.Error("session not accepted")
		}
	}))).ServeHTTP(rr, req)

	if sessionCookieOrNil(rr, a.sessionCookieName) == nil {
		t.Fatal("no renewal Set-Cookie, so this test proves nothing")
	}
	wantCacheHeaders(t, rr, "private, no-store", []string{"Cookie"})
}

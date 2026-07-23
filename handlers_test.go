package oidcauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

const (
	testClientID    = "test-client"
	testCookieKey   = "0123456789abcdef0123456789abcdef" // 32 bytes
	testRedirectURL = "http://localhost:8083/auth/callback"
)

func newTestAuth(t *testing.T, idp *fakeIDP, opts ...Option) *Auth {
	t.Helper()
	a, err := New(context.Background(), Config{
		Issuer:       idp.srv.URL,
		ClientID:     testClientID,
		ClientSecret: "test-secret",
		RedirectURL:  testRedirectURL,
		CookieSecret: testCookieKey,
	}, opts...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return a
}

// startLogin drives LoginHandler and returns the parsed authorization
// URL and the state cookie it set.
func startLogin(t *testing.T, a *Auth, target string) (*url.URL, *http.Cookie) {
	t.Helper()
	rr := httptest.NewRecorder()
	a.LoginHandler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, target, nil))
	if rr.Code != http.StatusFound {
		t.Fatalf("login status = %d, want 302", rr.Code)
	}
	authURL, err := url.Parse(rr.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse auth URL: %v", err)
	}
	var stateCookie *http.Cookie
	for _, c := range rr.Result().Cookies() {
		if c.Name == a.stateCookieName() {
			stateCookie = c
		}
	}
	if stateCookie == nil {
		t.Fatalf("login set no state cookie")
	}
	return authURL, stateCookie
}

// finishLogin drives CallbackHandler as the IdP redirect would, using
// the state from authURL, and returns the response.
func finishLogin(t *testing.T, a *Auth, idp *fakeIDP, authURL *url.URL, stateCookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	if _, ok := idp.claims["nonce"]; !ok {
		idp.claims["nonce"] = authURL.Query().Get("nonce")
	}
	cb := "/auth/callback?" + url.Values{
		"state": {authURL.Query().Get("state")},
		"code":  {"test-code"},
	}.Encode()
	req := httptest.NewRequest(http.MethodGet, cb, nil)
	req.AddCookie(stateCookie)
	rr := httptest.NewRecorder()
	a.CallbackHandler().ServeHTTP(rr, req)
	return rr
}

func sessionCookie(t *testing.T, a *Auth, rr *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, c := range rr.Result().Cookies() {
		if c.Name == a.sessionCookieName && c.Value != "" {
			return c
		}
	}
	return nil
}

func TestLoginHandlerAuthRequest(t *testing.T) {
	idp := newFakeIDP(t)
	a := newTestAuth(t, idp)

	authURL, stateCookie := startLogin(t, a, "/auth/login?next=/private")
	q := authURL.Query()

	if got := q.Get("client_id"); got != testClientID {
		t.Errorf("client_id = %q, want %q", got, testClientID)
	}
	if got := q.Get("redirect_uri"); got != testRedirectURL {
		t.Errorf("redirect_uri = %q", got)
	}
	if got := q.Get("response_type"); got != "code" {
		t.Errorf("response_type = %q, want code", got)
	}
	if got := q.Get("code_challenge_method"); got != "S256" {
		t.Errorf("code_challenge_method = %q, want S256", got)
	}
	for _, p := range []string{"state", "nonce", "code_challenge"} {
		if q.Get(p) == "" {
			t.Errorf("auth URL missing %s", p)
		}
	}
	if !strings.Contains(q.Get("scope"), "openid") {
		t.Errorf("scope %q missing openid", q.Get("scope"))
	}
	for _, p := range []string{"prompt", "approval_prompt"} {
		if q.Get(p) != "" {
			t.Errorf("unforced login must not send %s", p)
		}
	}

	// The state cookie must bind state and nonce and record next.
	st, err := a.stateFromRequest(requestWithCookie(stateCookie))
	if err != nil {
		t.Fatalf("state cookie unreadable: %v", err)
	}
	if st.State != q.Get("state") || st.Nonce != q.Get("nonce") {
		t.Errorf("state cookie does not match auth URL params")
	}
	if st.Next != "/private" {
		t.Errorf("next = %q, want /private", st.Next)
	}

	// The PKCE challenge must be S256(verifier).
	sum := sha256.Sum256([]byte(st.Verifier))
	if want := base64.RawURLEncoding.EncodeToString(sum[:]); q.Get("code_challenge") != want {
		t.Errorf("code_challenge is not S256 of the cookie verifier")
	}
}

func requestWithCookie(c *http.Cookie) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(c)
	return req
}

func TestCallbackHappyPath(t *testing.T) {
	idp := newFakeIDP(t)
	a := newTestAuth(t, idp)

	authURL, stateCookie := startLogin(t, a, "/auth/login?next=/private")
	rr := finishLogin(t, a, idp, authURL, stateCookie)

	if rr.Code != http.StatusFound {
		t.Fatalf("callback status = %d (%s), want 302", rr.Code, rr.Body.String())
	}
	if loc := rr.Header().Get("Location"); loc != "/private" {
		t.Errorf("redirect = %q, want /private", loc)
	}

	// PKCE verifier must be sent on exchange.
	if idp.lastTokenForm.Get("code_verifier") == "" {
		t.Errorf("token exchange sent no code_verifier")
	}

	// Session cookie must carry the verified claims.
	sc := sessionCookie(t, a, rr)
	if sc == nil {
		t.Fatalf("callback set no session cookie")
	}
	u, err := a.sessionUser(requestWithCookie(sc))
	if err != nil {
		t.Fatalf("session unreadable: %v", err)
	}
	want := User{Sub: "test-sub-1", Email: "user@example.com", EmailVerified: true, Name: "Test User"}
	if u != want {
		t.Errorf("session user = %+v, want %+v", u, want)
	}

	// The state cookie must be cleared (one-shot).
	cleared := false
	for _, c := range rr.Result().Cookies() {
		if c.Name == a.stateCookieName() && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Errorf("state cookie not cleared by callback")
	}
}

func TestCallbackRejectsStateMismatch(t *testing.T) {
	idp := newFakeIDP(t)
	a := newTestAuth(t, idp)

	_, stateCookie := startLogin(t, a, "/auth/login")
	req := httptest.NewRequest(http.MethodGet, "/auth/callback?state=forged&code=test-code", nil)
	req.AddCookie(stateCookie)
	rr := httptest.NewRecorder()
	a.CallbackHandler().ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rr.Code)
	}
	if sessionCookie(t, a, rr) != nil {
		t.Errorf("session cookie set despite state mismatch")
	}
}

func TestCallbackRejectsMissingStateCookie(t *testing.T) {
	idp := newFakeIDP(t)
	a := newTestAuth(t, idp)

	req := httptest.NewRequest(http.MethodGet, "/auth/callback?state=x&code=y", nil)
	rr := httptest.NewRecorder()
	a.CallbackHandler().ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rr.Code)
	}
}

func TestCallbackRejectsExpiredStateCookie(t *testing.T) {
	idp := newFakeIDP(t)
	a := newTestAuth(t, idp)

	authURL, stateCookie := startLogin(t, a, "/auth/login")
	a.now = func() time.Time { return time.Now().Add(stateTTL + time.Minute) }
	rr := finishLogin(t, a, idp, authURL, stateCookie)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rr.Code)
	}
}

func TestCallbackRejectsBadNonce(t *testing.T) {
	idp := newFakeIDP(t)
	a := newTestAuth(t, idp)

	authURL, stateCookie := startLogin(t, a, "/auth/login")
	idp.claims["nonce"] = "not-the-nonce"
	rr := finishLogin(t, a, idp, authURL, stateCookie)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d (%s), want 401", rr.Code, rr.Body.String())
	}
	if sessionCookie(t, a, rr) != nil {
		t.Errorf("session cookie set despite nonce mismatch")
	}
}

// TestCallbackRejectsWrongAudience is the library-level audience check:
// a token minted for another client must fail verification here.
func TestCallbackRejectsWrongAudience(t *testing.T) {
	idp := newFakeIDP(t)
	a := newTestAuth(t, idp)

	authURL, stateCookie := startLogin(t, a, "/auth/login")
	idp.claims["aud"] = "some-other-client"
	rr := finishLogin(t, a, idp, authURL, stateCookie)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d (%s), want 401", rr.Code, rr.Body.String())
	}
	if sessionCookie(t, a, rr) != nil {
		t.Errorf("session cookie set despite audience mismatch")
	}
}

func TestCallbackReportsIdPError(t *testing.T) {
	idp := newFakeIDP(t)
	a := newTestAuth(t, idp)

	_, stateCookie := startLogin(t, a, "/auth/login")
	req := httptest.NewRequest(http.MethodGet, "/auth/callback?error=access_denied", nil)
	req.AddCookie(stateCookie)
	rr := httptest.NewRecorder()
	a.CallbackHandler().ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rr.Code)
	}
}

func TestForceApprovalIfNewUser(t *testing.T) {
	idp := newFakeIDP(t)
	known := map[string]bool{}
	a := newTestAuth(t, idp, ForceApprovalIfNewUser(func(sub string) bool { return known[sub] }))

	// Unknown sub: the callback restarts login with force=1 instead of
	// creating a session.
	authURL, stateCookie := startLogin(t, a, "/auth/login?next=/private")
	rr := finishLogin(t, a, idp, authURL, stateCookie)
	if rr.Code != http.StatusFound {
		t.Fatalf("status = %d (%s), want 302", rr.Code, rr.Body.String())
	}
	loc, err := url.Parse(rr.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if loc.Path != a.loginPath || loc.Query().Get("force") != "1" {
		t.Fatalf("redirect = %q, want %s?force=1", loc, a.loginPath)
	}
	if loc.Query().Get("next") != "/private" {
		t.Errorf("restart lost next: %q", loc)
	}
	if sessionCookie(t, a, rr) != nil {
		t.Fatalf("session cookie set before forced consent")
	}

	// The forced login must carry both consent-forcing parameters:
	// the standard OIDC one and the pre-OIDC one, so any conformant
	// issuer honors whichever it recognizes.
	authURL2, stateCookie2 := startLogin(t, a, loc.String())
	if got := authURL2.Query().Get("prompt"); got != "consent" {
		t.Errorf("forced login prompt = %q, want consent", got)
	}
	if got := authURL2.Query().Get("approval_prompt"); got != "force" {
		t.Errorf("forced login approval_prompt = %q, want force", got)
	}

	// Second callback: sub is still unknown (the app records it only
	// after login), but the Forced flag must prevent a loop.
	delete(idp.claims, "nonce")
	rr2 := finishLogin(t, a, idp, authURL2, stateCookie2)
	if rr2.Code != http.StatusFound {
		t.Fatalf("forced callback status = %d (%s), want 302", rr2.Code, rr2.Body.String())
	}
	if loc := rr2.Header().Get("Location"); loc != "/private" {
		t.Errorf("forced callback redirect = %q, want /private", loc)
	}
	if sessionCookie(t, a, rr2) == nil {
		t.Fatalf("forced callback set no session cookie")
	}
}

// TestWithForceConsentParams covers the escape hatch for issuers that
// reject the default prompt + approval_prompt combination.
func TestWithForceConsentParams(t *testing.T) {
	idp := newFakeIDP(t)
	a := newTestAuth(t, idp,
		ForceApprovalIfNewUser(func(string) bool { return false }),
		WithForceConsentParams(map[string]string{"prompt": "consent"}))

	authURL, _ := startLogin(t, a, "/auth/login?force=1")
	if got := authURL.Query().Get("prompt"); got != "consent" {
		t.Errorf("prompt = %q, want consent", got)
	}
	if got := authURL.Query().Get("approval_prompt"); got != "" {
		t.Errorf("approval_prompt = %q, want absent after override", got)
	}
}

func TestLogoutClearsSession(t *testing.T) {
	idp := newFakeIDP(t)
	a := newTestAuth(t, idp)

	rr := httptest.NewRecorder()
	a.LogoutHandler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/auth/logout", nil))
	if rr.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rr.Code)
	}
	cleared := false
	for _, c := range rr.Result().Cookies() {
		if c.Name == a.sessionCookieName && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Errorf("logout did not clear the session cookie")
	}
}

func TestSanitizeNext(t *testing.T) {
	cases := map[string]string{
		"":                       "/",
		"/private":               "/private",
		"/a/b?x=1":               "/a/b?x=1",
		"//evil.example.com":     "/",
		"https://evil.example":   "/",
		"javascript:alert(1)":    "/",
		"/ok\\..\\backslash":     "/",
		"/crlf\r\nSet-Cookie: x": "/",
	}
	for in, want := range cases {
		if got := sanitizeNext(in); got != want {
			t.Errorf("sanitizeNext(%q) = %q, want %q", in, got, want)
		}
	}
}

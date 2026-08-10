package oidcauth

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"
)

// TestOptionSettersApply exercises the success path of every functional
// option directly against a bare Auth, asserting each writes its field.
func TestOptionSettersApply(t *testing.T) {
	known := func(string, string) bool { return true }
	a := &Auth{}
	opts := []Option{
		WithSessionTTL(2 * time.Hour),
		WithCookieName("_sess"),
		WithLoginPath("/in"),
		WithLogoutPath("/out"),
		WithPostLogoutRedirect("/bye"),
		ForceApprovalIfNewUser(known),
		WithForceConsentParams(map[string]string{"prompt": "consent"}),
		WithExtraClaims("groups", "roles"),
	}
	for _, opt := range opts {
		if err := opt(a); err != nil {
			t.Fatalf("option returned error: %v", err)
		}
	}

	if a.sessionTTL != 2*time.Hour {
		t.Errorf("sessionTTL = %v, want 2h", a.sessionTTL)
	}
	if a.sessionCookieName != "_sess" {
		t.Errorf("sessionCookieName = %q, want _sess", a.sessionCookieName)
	}
	if a.loginPath != "/in" {
		t.Errorf("loginPath = %q, want /in", a.loginPath)
	}
	if a.logoutPath != "/out" {
		t.Errorf("logoutPath = %q, want /out", a.logoutPath)
	}
	if a.postLogoutRedirect != "/bye" {
		t.Errorf("postLogoutRedirect = %q, want /bye", a.postLogoutRedirect)
	}
	if a.knownSub == nil || !a.knownSub("iss", "x") {
		t.Errorf("knownSub not set")
	}
	if len(a.forceConsentParams) != 1 || a.forceConsentParams["prompt"] != "consent" {
		t.Errorf("forceConsentParams = %v, want {prompt:consent}", a.forceConsentParams)
	}
	if !reflect.DeepEqual(a.extraClaims, []string{"groups", "roles"}) {
		t.Errorf("extraClaims = %v, want [groups roles]", a.extraClaims)
	}
}

// TestOptionSettersCloneInputs pins the defensive copy: mutating the
// caller's map or slice after the option runs must not affect the Auth.
func TestOptionSettersCloneInputs(t *testing.T) {
	params := map[string]string{"prompt": "consent"}
	names := []string{"groups"}
	a := &Auth{}
	if err := WithForceConsentParams(params)(a); err != nil {
		t.Fatal(err)
	}
	if err := WithExtraClaims(names...)(a); err != nil {
		t.Fatal(err)
	}

	params["prompt"] = "mutated"
	names[0] = "mutated"
	if a.forceConsentParams["prompt"] != "consent" {
		t.Errorf("forceConsentParams aliases the caller's map")
	}
	if a.extraClaims[0] != "groups" {
		t.Errorf("extraClaims aliases the caller's slice")
	}
}

// TestOptionValidation covers the rejection branch of every option that
// validates its input.
func TestOptionValidation(t *testing.T) {
	cases := map[string]Option{
		"zero session TTL":     WithSessionTTL(0),
		"negative session TTL": WithSessionTTL(-time.Second),
		"empty cookie name":    WithCookieName(""),
		"relative login path":  WithLoginPath("in"),
		"relative logout path": WithLogoutPath("out"),
		"relative post-logout": WithPostLogoutRedirect("bye"),
		"nil known func":       ForceApprovalIfNewUser(nil),
		"empty consent params": WithForceConsentParams(nil),
		"no extra claim names": WithExtraClaims(),
	}
	for name, opt := range cases {
		if err := opt(&Auth{}); err == nil {
			t.Errorf("%s: expected an error, got nil", name)
		}
	}
}

// TestPathAccessors covers the exported path getters.
func TestPathAccessors(t *testing.T) {
	idp := newFakeIDP(t)
	a := newTestAuth(t, idp)

	if a.LoginPath() != a.loginPath {
		t.Errorf("LoginPath() = %q, want %q", a.LoginPath(), a.loginPath)
	}
	if a.CallbackPath() != a.callbackPath {
		t.Errorf("CallbackPath() = %q, want %q", a.CallbackPath(), a.callbackPath)
	}
	if a.LogoutPath() != a.logoutPath {
		t.Errorf("LogoutPath() = %q, want %q", a.LogoutPath(), a.logoutPath)
	}
}

// TestMount verifies Mount wires each handler at its configured path by
// probing behavior unique to each: login redirects, logout rejects GET,
// and the callback rejects a request with no state cookie.
func TestMount(t *testing.T) {
	idp := newFakeIDP(t)
	a := newTestAuth(t, idp)
	mux := http.NewServeMux()
	a.Mount(mux)

	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, a.LoginPath(), nil))
	if rr.Code != http.StatusFound {
		t.Errorf("mounted login: status = %d, want 302", rr.Code)
	}

	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, a.LogoutPath(), nil))
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("mounted logout: status = %d, want 405", rr.Code)
	}

	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, a.CallbackPath(), nil))
	if rr.Code != http.StatusBadRequest {
		t.Errorf("mounted callback: status = %d, want 400", rr.Code)
	}
}

// TestNewFromEnv covers the env-shorthand constructor: the success path
// through discovery, and the missing-variable path that fails before it.
func TestNewFromEnv(t *testing.T) {
	idp := newFakeIDP(t)
	for k, v := range map[string]string{
		"AUTH_ISSUER":        idp.srv.URL,
		"AUTH_CLIENT_ID":     testClientID,
		"AUTH_CLIENT_SECRET": "test-secret",
		"AUTH_REDIRECT_URL":  testRedirectURL,
		"AUTH_COOKIE_SECRET": testCookieKey,
	} {
		t.Setenv(k, v)
	}
	a, err := NewFromEnv(t.Context())
	if err != nil {
		t.Fatalf("NewFromEnv: %v", err)
	}
	if a.oauth.ClientID != testClientID {
		t.Errorf("ClientID = %q, want %q", a.oauth.ClientID, testClientID)
	}

	// A missing variable must surface the FromEnv error without discovery.
	t.Setenv("AUTH_ISSUER", "")
	if _, err := NewFromEnv(t.Context()); err == nil {
		t.Error("NewFromEnv succeeded with AUTH_ISSUER unset")
	}
}

// TestNewRejectsBadRedirectURL covers New's redirect-parse error branch.
func TestNewRejectsBadRedirectURL(t *testing.T) {
	_, err := New(t.Context(), Config{
		Issuer: "https://auth.example.com", ClientID: "app", ClientSecret: "s",
		RedirectURL: "https://app.example.com", CookieSecret: testCookieKey,
	})
	if err == nil {
		t.Error("New accepted a root-path redirect URL")
	}
}

// TestNewReportsDiscoveryFailure covers New's discovery error branch: a
// reachable server that serves no discovery document.
func TestNewReportsDiscoveryFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "no discovery here", http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)

	_, err := New(t.Context(), Config{
		Issuer: srv.URL, ClientID: "app", ClientSecret: "s",
		RedirectURL: testRedirectURL, CookieSecret: testCookieKey,
	})
	if err == nil {
		t.Error("New succeeded despite failed discovery")
	}
}

// TestNewRejectsBadOption covers New's option-error branch: a failing
// option aborts construction before discovery is attempted.
func TestNewRejectsBadOption(t *testing.T) {
	idp := newFakeIDP(t)
	_, err := New(t.Context(), Config{
		Issuer: idp.srv.URL, ClientID: testClientID, ClientSecret: "test-secret",
		RedirectURL: testRedirectURL, CookieSecret: testCookieKey,
	}, WithCookieName(""))
	if err == nil {
		t.Error("New accepted an invalid option")
	}
}

// TestSessionClearer proves the network-free clear: no discovery
// endpoint exists, yet the returned function emits the same
// cookie-clearing Set-Cookie an Auth would, honoring options.
func TestSessionClearer(t *testing.T) {
	cfg := Config{
		Issuer: "https://unreachable.invalid", ClientID: "app", ClientSecret: "s",
		RedirectURL: testRedirectURL, CookieSecret: testCookieKey,
	}
	clear, err := SessionClearer(cfg, WithCookieName("_sess"))
	if err != nil {
		t.Fatalf("SessionClearer: %v", err)
	}
	rr := httptest.NewRecorder()
	clear(rr)
	cookies := rr.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("got %d cookies, want 1", len(cookies))
	}
	c := cookies[0]
	if c.Name != "_sess" || c.Value != "" || c.MaxAge != -1 {
		t.Errorf("clear cookie = %+v, want _sess cleared with MaxAge=-1", c)
	}

	// Validation happens at construction, exactly like New.
	if _, err := SessionClearer(cfg, WithCookieName("")); err == nil {
		t.Error("SessionClearer accepted an invalid option")
	}
	if _, err := SessionClearer(Config{}); err == nil {
		t.Error("SessionClearer accepted an empty config")
	}
}

// TestSessionReader proves the network-free read: a session cookie set
// by an offline-constructed Auth verifies through SessionReader built
// from the same config, and fails closed on tampering and on absence.
func TestSessionReader(t *testing.T) {
	cfg := Config{
		Issuer: "https://unreachable.invalid", ClientID: "app", ClientSecret: "s",
		RedirectURL: testRedirectURL, CookieSecret: testCookieKey,
	}
	a, err := newAuth(cfg)
	if err != nil {
		t.Fatalf("newAuth: %v", err)
	}
	rr := httptest.NewRecorder()
	a.setSessionCookie(rr, User{Issuer: "https://idp.example.com", Sub: "u1"})
	cookies := rr.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("got %d cookies, want 1", len(cookies))
	}

	read, err := SessionReader(cfg)
	if err != nil {
		t.Fatalf("SessionReader: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(cookies[0])
	u, ok := read(req)
	if !ok || u.Sub != "u1" || u.Issuer != "https://idp.example.com" {
		t.Errorf("read = %+v, %v; want u1 session, true", u, ok)
	}

	// Fails closed: no cookie, and a tampered cookie.
	if _, ok := read(httptest.NewRequest(http.MethodGet, "/", nil)); ok {
		t.Error("read succeeded with no cookie")
	}
	bad := *cookies[0]
	bad.Value += "x"
	reqBad := httptest.NewRequest(http.MethodGet, "/", nil)
	reqBad.AddCookie(&bad)
	if _, ok := read(reqBad); ok {
		t.Error("read succeeded with a tampered cookie")
	}

	// Validation happens at construction, exactly like New.
	if _, err := SessionReader(Config{}); err == nil {
		t.Error("SessionReader accepted an empty config")
	}
}

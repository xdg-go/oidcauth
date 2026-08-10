package oidcauth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"sync/atomic"
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

// TestNewFromEnv covers the env-shorthand constructor: the success
// path, and the missing-variable path.
func TestNewFromEnv(t *testing.T) {
	for k, v := range map[string]string{
		"AUTH_ISSUER":        "https://auth.example.com",
		"AUTH_CLIENT_ID":     testClientID,
		"AUTH_CLIENT_SECRET": "test-secret",
		"AUTH_REDIRECT_URL":  testRedirectURL,
		"AUTH_COOKIE_SECRET": testCookieKey,
	} {
		t.Setenv(k, v)
	}
	a, err := NewFromEnv()
	if err != nil {
		t.Fatalf("NewFromEnv: %v", err)
	}
	if a.oauth.ClientID != testClientID {
		t.Errorf("ClientID = %q, want %q", a.oauth.ClientID, testClientID)
	}

	// A missing variable must surface the FromEnv error.
	t.Setenv("AUTH_ISSUER", "")
	if _, err := NewFromEnv(); err == nil {
		t.Error("NewFromEnv succeeded with AUTH_ISSUER unset")
	}
}

// TestNewRejectsBadRedirectURL covers New's redirect-parse error branch.
func TestNewRejectsBadRedirectURL(t *testing.T) {
	_, err := New(Config{
		Issuer: "https://auth.example.com", ClientID: "app", ClientSecret: "s",
		RedirectURL: "https://app.example.com", CookieSecret: testCookieKey,
	})
	if err == nil {
		t.Error("New accepted a root-path redirect URL")
	}
}

// TestNewRejectsBadOption covers New's option-error branch.
func TestNewRejectsBadOption(t *testing.T) {
	_, err := New(Config{
		Issuer: "https://auth.example.com", ClientID: testClientID, ClientSecret: "test-secret",
		RedirectURL: testRedirectURL, CookieSecret: testCookieKey,
	}, WithCookieName(""))
	if err == nil {
		t.Error("New accepted an invalid option")
	}
}

// TestNewIsOffline proves construction needs no network: with an
// unreachable issuer, New succeeds and the discovery-free surface —
// session read via User, session clear via ClearSession — works.
func TestNewIsOffline(t *testing.T) {
	a, err := New(Config{
		Issuer: "https://unreachable.invalid", ClientID: "app", ClientSecret: "s",
		RedirectURL: testRedirectURL, CookieSecret: testCookieKey,
	}, WithCookieName("_sess"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Mint a session directly (test-only shortcut past the callback)
	// and read it back: verification is HMAC-anchored, not issuer-anchored.
	rr := httptest.NewRecorder()
	a.setSessionCookie(rr, User{Issuer: "https://idp.example.com", Sub: "u1"})
	cookies := rr.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("got %d cookies, want 1", len(cookies))
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(cookies[0])
	u, ok := a.User(req)
	if !ok || u.Sub != "u1" || u.Issuer != "https://idp.example.com" {
		t.Errorf("User = %+v, %v; want u1 session, true", u, ok)
	}

	rr = httptest.NewRecorder()
	a.ClearSession(rr)
	cookies = rr.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != "_sess" ||
		cookies[0].Value != "" || cookies[0].MaxAge != -1 {
		t.Errorf("clear cookies = %+v, want _sess cleared with MaxAge=-1", cookies)
	}
}

// TestConnect covers eager discovery: failure against a down issuer,
// then success — and idempotence — once the issuer recovers.
func TestConnect(t *testing.T) {
	idp := newFakeIDP(t)
	idp.discoveryStatus.Store(http.StatusInternalServerError)
	a := newTestAuth(t, idp)

	if err := a.Connect(t.Context()); err == nil {
		t.Fatal("Connect succeeded despite failed discovery")
	}

	idp.discoveryStatus.Store(0)
	a.now = func() time.Time { return time.Now().Add(discoveryCooldown) } // skip cooldown
	if err := a.Connect(t.Context()); err != nil {
		t.Fatalf("Connect after issuer recovery: %v", err)
	}
	count := idp.discoveryCount.Load()
	if err := a.Connect(t.Context()); err != nil {
		t.Fatalf("second Connect: %v", err)
	}
	if idp.discoveryCount.Load() != count {
		t.Error("Connect after success hit the discovery endpoint again")
	}
}

// TestLazyDiscoveryCooldown proves failure caching: while the issuer
// is down, requests inside the cooldown window share one failed
// attempt's error; after the cooldown (and issuer recovery) a fresh
// attempt succeeds.
func TestLazyDiscoveryCooldown(t *testing.T) {
	idp := newFakeIDP(t)
	idp.discoveryStatus.Store(http.StatusInternalServerError)
	a := newTestAuth(t, idp)

	get := func() int {
		rr := httptest.NewRecorder()
		a.LoginHandler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/auth/login", nil))
		return rr.Code
	}

	if code := get(); code != http.StatusServiceUnavailable {
		t.Fatalf("login during outage: status = %d, want 503", code)
	}
	count := idp.discoveryCount.Load()
	if code := get(); code != http.StatusServiceUnavailable {
		t.Fatalf("login inside cooldown: status = %d, want 503", code)
	}
	if idp.discoveryCount.Load() != count {
		t.Error("request inside cooldown triggered a new discovery attempt")
	}

	idp.discoveryStatus.Store(0)
	a.now = func() time.Time { return time.Now().Add(discoveryCooldown) } // expire cooldown
	if code := get(); code != http.StatusFound {
		t.Errorf("login after recovery: status = %d, want 302", code)
	}
}

// TestCallbackGatedOnDiscovery proves the callback 503s during an
// issuer outage without burning the one-shot state cookie.
func TestCallbackGatedOnDiscovery(t *testing.T) {
	idp := newFakeIDP(t)
	a := newTestAuth(t, idp)
	authURL, stateCookie := startLogin(t, a, "/auth/login")

	// Outage between login and callback: reset to an undiscovered Auth
	// pointed at a down issuer, keeping the same cookie secret.
	idp.discoveryStatus.Store(http.StatusInternalServerError)
	a2 := newTestAuth(t, idp)

	rr := finishLogin(t, a2, idp, authURL, stateCookie)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("callback during outage: status = %d, want 503", rr.Code)
	}
	for _, c := range rr.Result().Cookies() {
		if c.Name == a2.stateCookieName() && c.MaxAge < 0 {
			t.Error("callback cleared the state cookie despite the 503")
		}
	}

	// Issuer recovers: the same state cookie completes the login.
	idp.discoveryStatus.Store(0)
	a2.now = func() time.Time { return time.Now().Add(discoveryCooldown) }
	rr = finishLogin(t, a2, idp, authURL, stateCookie)
	if rr.Code != http.StatusFound {
		t.Errorf("callback after recovery: status = %d, want 302", rr.Code)
	}
}

// TestDiscoverySingleflight proves concurrent requests share one
// discovery attempt.
func TestDiscoverySingleflight(t *testing.T) {
	idp := newFakeIDP(t)
	a := newTestAuth(t, idp)

	const n = 8
	var wg sync.WaitGroup
	for range n {
		wg.Go(func() {
			if err := a.ensureDiscovered(t.Context()); err != nil {
				t.Errorf("ensureDiscovered: %v", err)
			}
		})
	}
	wg.Wait()
	if got := idp.discoveryCount.Load(); got != 1 {
		t.Errorf("discovery requests = %d, want 1", got)
	}
}

// TestDiscoveryAbandonedWait proves the wait/flight split: a caller's
// ctx bounds only its own wait, not the shared flight. An impatient
// caller gets ctx.Err() while the attempt stays in-flight; a patient
// caller still receives that same attempt's eventual success.
func TestDiscoveryAbandonedWait(t *testing.T) {
	idp := newFakeIDP(t)
	gate := make(chan struct{})
	idp.discoveryHook = func() { <-gate } // hold every discovery request; only one occurs
	a := newTestAuth(t, idp)

	// Patient caller: waits out the gated flight.
	patient := make(chan error, 1)
	go func() { patient <- a.ensureDiscovered(context.Background()) }()

	// Hold until the flight is on the wire, so both callers share it.
	waitFor(t, func() bool { return idp.discoveryCount.Load() == 1 })

	// Impatient caller: canceled ctx returns immediately with ctx.Err().
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := a.ensureDiscovered(ctx); !errors.Is(err, context.Canceled) {
		t.Errorf("abandoned wait: err = %v, want context.Canceled", err)
	}

	// Releasing the gate completes the flight for the patient caller.
	close(gate)
	if err := <-patient; err != nil {
		t.Errorf("patient caller: err = %v, want nil", err)
	}
	if got := idp.discoveryCount.Load(); got != 1 {
		t.Errorf("discovery requests = %d, want 1", got)
	}
}

// TestDiscoverVerifierWriteOnce races two direct discover() calls
// (bypassing singleflight) to exercise the post-network re-check: the
// loser must keep the winner's verifier rather than rewrite it.
func TestDiscoverVerifierWriteOnce(t *testing.T) {
	idp := newFakeIDP(t)
	gate := make(chan struct{})
	var reqs atomic.Int32
	idp.discoveryHook = func() { // hold only the first request; the second must win the race
		if reqs.Add(1) == 1 {
			<-gate
		}
	}
	a := newTestAuth(t, idp)

	// First attempt: held on the network by the gate.
	first := make(chan error, 1)
	go func() { first <- a.discover() }()
	waitFor(t, func() bool { return idp.discoveryCount.Load() == 1 })

	// Second attempt runs to completion and wins.
	if err := a.discover(); err != nil {
		t.Fatalf("second discover: %v", err)
	}
	a.mu.Lock()
	winner := a.verifier
	a.mu.Unlock()

	// The first attempt returns from the network, sees the winner, and
	// must leave it in place.
	close(gate)
	if err := <-first; err != nil {
		t.Errorf("first discover: err = %v, want nil", err)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.verifier != winner {
		t.Error("losing discover attempt rewrote the verifier")
	}
}

// waitFor polls cond until it holds or the test deadline nears.
func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met within 5s")
		}
		time.Sleep(time.Millisecond)
	}
}

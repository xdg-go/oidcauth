package oidcauth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// cookieAuth builds an Auth with just enough state for cookie tests,
// skipping OIDC discovery.
func cookieAuth(secret string) *Auth {
	return &Auth{
		cookieSecret:      []byte(secret),
		secureCookies:     true,
		sessionCookieName: "_oidcauth",
		sessionTTL:        time.Hour,
		now:               time.Now,
	}
}

func recordedCookie(t *testing.T, rr *httptest.ResponseRecorder, name string) *http.Cookie {
	t.Helper()
	for _, c := range rr.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("cookie %s not set", name)
	return nil
}

func TestSessionCookieRoundTrip(t *testing.T) {
	a := cookieAuth(testCookieKey)
	want := User{Sub: "s1", Email: "e@example.com", EmailVerified: true, Name: "N"}

	rr := httptest.NewRecorder()
	a.setSessionCookie(rr, want)
	c := recordedCookie(t, rr, a.sessionCookieName)

	if !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteLaxMode {
		t.Errorf("cookie flags: HttpOnly=%v Secure=%v SameSite=%v", c.HttpOnly, c.Secure, c.SameSite)
	}
	got, err := a.sessionUser(requestWithCookie(c))
	if err != nil {
		t.Fatalf("sessionUser: %v", err)
	}
	if got != want {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func TestSessionCookieInsecureForHTTPDev(t *testing.T) {
	a := cookieAuth(testCookieKey)
	a.secureCookies = false
	rr := httptest.NewRecorder()
	a.setSessionCookie(rr, User{Sub: "s"})
	if c := recordedCookie(t, rr, a.sessionCookieName); c.Secure {
		t.Errorf("dev (http) cookie must not set Secure")
	}
}

func TestSessionCookieTamperDetected(t *testing.T) {
	a := cookieAuth(testCookieKey)
	rr := httptest.NewRecorder()
	a.setSessionCookie(rr, User{Sub: "s1"})
	c := recordedCookie(t, rr, a.sessionCookieName)

	// Flip a payload character; the HMAC must catch it.
	mutated := *c
	if mutated.Value[0] == 'A' {
		mutated.Value = "B" + mutated.Value[1:]
	} else {
		mutated.Value = "A" + mutated.Value[1:]
	}
	if _, err := a.sessionUser(requestWithCookie(&mutated)); err == nil {
		t.Errorf("tampered cookie accepted")
	}

	for name, mangle := range map[string]func(string) string{
		"no separator":  func(v string) string { return strings.ReplaceAll(v, ".", "") },
		"empty":         func(string) string { return "" },
		"truncated sig": func(v string) string { return v[:len(v)-4] },
		"junk":          func(string) string { return "!!!.@@@" },
	} {
		mutated := *c
		mutated.Value = mangle(c.Value)
		if _, err := a.sessionUser(requestWithCookie(&mutated)); err == nil {
			t.Errorf("%s: mangled cookie accepted", name)
		}
	}
}

func TestSessionCookieWrongKeyRejected(t *testing.T) {
	a := cookieAuth(testCookieKey)
	rr := httptest.NewRecorder()
	a.setSessionCookie(rr, User{Sub: "s1"})
	c := recordedCookie(t, rr, a.sessionCookieName)

	other := cookieAuth("ffffffffffffffffffffffffffffffff")
	if _, err := other.sessionUser(requestWithCookie(c)); err == nil {
		t.Errorf("cookie signed with different key accepted")
	}
}

func TestSessionCookieExpiryEnforced(t *testing.T) {
	a := cookieAuth(testCookieKey)
	rr := httptest.NewRecorder()
	a.setSessionCookie(rr, User{Sub: "s1"})
	c := recordedCookie(t, rr, a.sessionCookieName)

	a.now = func() time.Time { return time.Now().Add(a.sessionTTL + time.Minute) }
	if _, err := a.sessionUser(requestWithCookie(c)); err == nil {
		t.Errorf("expired session accepted")
	}
}

// TestPurposeSeparation ensures a signed state cookie cannot be
// replayed as a session cookie: same key, different HMAC purpose.
func TestPurposeSeparation(t *testing.T) {
	a := cookieAuth(testCookieKey)
	rr := httptest.NewRecorder()
	a.setStateCookie(rr, statePayload{State: "s", Nonce: "n"})
	stateC := recordedCookie(t, rr, a.stateCookieName())

	forged := &http.Cookie{Name: a.sessionCookieName, Value: stateC.Value}
	if _, err := a.sessionUser(requestWithCookie(forged)); err == nil {
		t.Errorf("state cookie accepted as session cookie")
	}
}

func TestFromEnv(t *testing.T) {
	vars := map[string]string{
		"AUTH_ISSUER":        "https://auth.example.com",
		"AUTH_CLIENT_ID":     "app",
		"AUTH_CLIENT_SECRET": "secret",
		"AUTH_REDIRECT_URL":  "https://app.example.com/auth/callback",
		"AUTH_COOKIE_SECRET": testCookieKey,
	}
	for k, v := range vars {
		t.Setenv(k, v)
	}
	cfg, err := FromEnv()
	if err != nil {
		t.Fatalf("FromEnv: %v", err)
	}
	if cfg.Issuer != vars["AUTH_ISSUER"] || cfg.ClientID != vars["AUTH_CLIENT_ID"] {
		t.Errorf("cfg = %+v", cfg)
	}

	t.Setenv("AUTH_CLIENT_SECRET", "")
	t.Setenv("AUTH_COOKIE_SECRET", "")
	_, err = FromEnv()
	if err == nil {
		t.Fatal("FromEnv succeeded with missing vars")
	}
	for _, name := range []string{"AUTH_CLIENT_SECRET", "AUTH_COOKIE_SECRET"} {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("error %q does not name %s", err, name)
		}
	}
}

func TestNewRejectsShortCookieSecret(t *testing.T) {
	_, err := New(t.Context(), Config{
		Issuer: "https://auth.example.com", ClientID: "app", ClientSecret: "s",
		RedirectURL: "https://app.example.com/auth/callback", CookieSecret: "short",
	})
	if err == nil || !strings.Contains(err.Error(), "32 bytes") {
		t.Errorf("err = %v, want cookie-secret length error", err)
	}
}

func TestParseRedirectURL(t *testing.T) {
	cases := []struct {
		in      string
		path    string
		secure  bool
		wantErr bool
	}{
		{in: "https://app.example.com/auth/callback", path: "/auth/callback", secure: true},
		{in: "http://localhost:8083/auth/callback", path: "/auth/callback", secure: false},
		{in: "https://app.example.com/custom/cb", path: "/custom/cb", secure: true},
		{in: "https://app.example.com", wantErr: true},
		{in: "https://app.example.com/", wantErr: true},
		{in: "ftp://app.example.com/cb", wantErr: true},
		{in: "/auth/callback", wantErr: true},
		{in: "https://app.example.com/cb?x=1", wantErr: true},
		// Non-canonical paths must be rejected, not silently cleaned:
		// cleaning would desync the mount path from the redirect_uri.
		{in: "https://app.example.com/auth/callback/", wantErr: true},
		{in: "https://app.example.com/auth//callback", wantErr: true},
		{in: "https://app.example.com/auth/../auth/callback", wantErr: true},
	}
	for _, c := range cases {
		p, secure, err := parseRedirectURL(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("parseRedirectURL(%q): expected error", c.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseRedirectURL(%q): %v", c.in, err)
			continue
		}
		if p != c.path || secure != c.secure {
			t.Errorf("parseRedirectURL(%q) = (%q, %v), want (%q, %v)", c.in, p, secure, c.path, c.secure)
		}
	}
}

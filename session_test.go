package oidcauth

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

// cookieAuth builds an Auth with just enough state for cookie tests,
// skipping OIDC discovery.
// The variadic previous secrets are verify-only, mirroring
// Config.PreviousCookieSecrets.
func cookieAuth(secret string, previous ...string) *Auth {
	verifyKeys := [][]byte{[]byte(secret)}
	for _, prev := range previous {
		verifyKeys = append(verifyKeys, []byte(prev))
	}
	return &Auth{
		signingKey:         []byte(secret),
		verifyKeys:         verifyKeys,
		secureCookies:      true,
		sessionCookieName:  "_oidcauth",
		sessionLifetime:    time.Hour,
		renewWindow:        30 * time.Minute,
		maxSessionLifetime: 24 * time.Hour,
		logger:             slog.New(slog.DiscardHandler),
		now:                time.Now,
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
	c := recordedCookie(t, rr, a.sessionName())

	if !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteLaxMode {
		t.Errorf("cookie flags: HttpOnly=%v Secure=%v SameSite=%v", c.HttpOnly, c.Secure, c.SameSite)
	}
	s, err := a.sessionFromRequestAt(requestWithCookie(c), a.now())
	if err != nil {
		t.Fatalf("sessionFromRequestAt: %v", err)
	}
	got := s.User
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func TestSessionCookieInsecureForHTTPDev(t *testing.T) {
	a := cookieAuth(testCookieKey)
	a.secureCookies = false
	rr := httptest.NewRecorder()
	a.setSessionCookie(rr, User{Sub: "s"})
	if c := recordedCookie(t, rr, a.sessionName()); c.Secure {
		t.Errorf("dev (http) cookie must not set Secure")
	}
}

func TestSessionCookieTamperDetected(t *testing.T) {
	a := cookieAuth(testCookieKey)
	rr := httptest.NewRecorder()
	a.setSessionCookie(rr, User{Sub: "s1"})
	c := recordedCookie(t, rr, a.sessionName())

	// Flip a payload character; the HMAC must catch it.
	mutated := *c
	if mutated.Value[0] == 'A' {
		mutated.Value = "B" + mutated.Value[1:]
	} else {
		mutated.Value = "A" + mutated.Value[1:]
	}
	if _, err := a.sessionFromRequestAt(requestWithCookie(&mutated), a.now()); err == nil {
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
		if _, err := a.sessionFromRequestAt(requestWithCookie(&mutated), a.now()); err == nil {
			t.Errorf("%s: mangled cookie accepted", name)
		}
	}
}

// TestSessionCookieSignedGarbageRejected covers the unmarshal branch:
// a payload HMAC'd with the real key but not valid JSON.
func TestSessionCookieSignedGarbageRejected(t *testing.T) {
	a := cookieAuth(testCookieKey)
	c := &http.Cookie{
		Name:  a.sessionName(),
		Value: a.sign(purposeSession, []byte("not json")),
	}
	if _, err := a.sessionFromRequestAt(requestWithCookie(c), a.now()); err == nil {
		t.Error("signed non-JSON payload accepted")
	}
}

func TestSessionCookieWrongKeyRejected(t *testing.T) {
	a := cookieAuth(testCookieKey)
	rr := httptest.NewRecorder()
	a.setSessionCookie(rr, User{Sub: "s1"})
	c := recordedCookie(t, rr, a.sessionName())

	other := cookieAuth("ffffffffffffffffffffffffffffffff")
	if _, err := other.sessionFromRequestAt(requestWithCookie(c), other.now()); err == nil {
		t.Errorf("cookie signed with different key accepted")
	}
}

func TestSessionCookieExpiryEnforced(t *testing.T) {
	a := cookieAuth(testCookieKey)
	rr := httptest.NewRecorder()
	a.setSessionCookie(rr, User{Sub: "s1"})
	c := recordedCookie(t, rr, a.sessionName())

	a.now = func() time.Time { return time.Now().Add(a.sessionLifetime + time.Minute) }
	if _, err := a.sessionFromRequestAt(requestWithCookie(c), a.now()); err == nil {
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

	forged := &http.Cookie{Name: a.sessionName(), Value: stateC.Value}
	if _, err := a.sessionFromRequestAt(requestWithCookie(forged), a.now()); err == nil {
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
	_, err := New(Config{
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
		// A control character makes url.Parse itself fail.
		{in: "https://app.example.com/cb\x7f", wantErr: true},
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

// TestSessionPayloadIssuedAtRoundTrip pins the IssuedAt encoding: Unix
// seconds under "iat", so a mint time with sub-second components comes
// back truncated to the second.
func TestSessionPayloadIssuedAtRoundTrip(t *testing.T) {
	a := cookieAuth(testCookieKey)
	mint := time.Date(2026, 8, 21, 12, 34, 56, 789_000_000, time.UTC)
	a.now = func() time.Time { return mint }

	rr := httptest.NewRecorder()
	a.setSessionCookie(rr, User{Sub: "s1"})
	c := recordedCookie(t, rr, a.sessionName())

	payload, err := a.verify(purposeSession, c.Value)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	var s sessionPayload
	if err := json.Unmarshal(payload, &s); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if want := mint.Unix(); s.IssuedAt != want {
		t.Errorf("IssuedAt = %d, want %d", s.IssuedAt, want)
	}
	// Truncation is the point: the nanoseconds do not survive.
	if got := time.Unix(s.IssuedAt, 0).UTC(); !got.Equal(mint.Truncate(time.Second)) {
		t.Errorf("decoded IssuedAt = %v, want %v", got, mint.Truncate(time.Second))
	}
	if !strings.Contains(string(payload), `"iat":`) {
		t.Errorf("payload lacks iat key: %s", payload)
	}
}

// TestSessionPayloadAbsentIssuedAtIsZero pins the fail-closed
// sentinel: a payload with no "iat" field decodes to IssuedAt == 0.
func TestSessionPayloadAbsentIssuedAtIsZero(t *testing.T) {
	var s sessionPayload
	if err := json.Unmarshal([]byte(`{"user":{"sub":"s1"},"exp":"2030-01-01T00:00:00Z"}`), &s); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if s.IssuedAt != 0 {
		t.Errorf("absent iat decoded to %d, want 0", s.IssuedAt)
	}
}

// TestSessionCookieSingleClockReading guards against setSessionCookie
// sampling the clock TWICE -- once for Expiry and once for IssuedAt.
// Two readings can straddle a second boundary (or any skew), leaving a
// cookie whose Expiry-minus-TTL disagrees with its IssuedAt, which
// would corrupt any age computation built on the pair. Every other
// test stubs a.now as a CONSTANT, so it cannot see that bug at all:
// the advancing clock below is the entire point of this test. Do not
// "simplify" it back to a fixed instant.
func TestSessionCookieSingleClockReading(t *testing.T) {
	a := cookieAuth(testCookieKey)

	// Nth call to a.now returns base + N seconds. The mutex keeps the
	// counter race-free if this stub is ever shared across goroutines.
	base := time.Date(2026, 8, 21, 0, 0, 0, 0, time.UTC)
	var mu sync.Mutex
	calls := 0
	a.now = func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		calls++
		return base.Add(time.Duration(calls) * time.Second)
	}

	rr := httptest.NewRecorder()
	a.setSessionCookie(rr, User{Sub: "s1"})
	c := recordedCookie(t, rr, a.sessionName())

	payload, err := a.verify(purposeSession, c.Value)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	var s sessionPayload
	if err := json.Unmarshal(payload, &s); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got := s.Expiry.Add(-a.sessionLifetime).Unix(); got != s.IssuedAt {
		t.Errorf("Expiry-TTL = %d, IssuedAt = %d: derived from different clock readings", got, s.IssuedAt)
	}
}

// TestSessionIssuedAtRequired covers the fail-closed rule: only a
// payload carrying a positive "iat" is accepted. Each case mints its
// own signed cookie, so the signature is always valid and IssuedAt is
// the only variable.
func TestSessionIssuedAtRequired(t *testing.T) {
	mint := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)

	cases := []struct {
		name    string
		payload string
		wantErr error
	}{
		{
			name:    "absent iat",
			payload: `{"user":{"sub":"s1"},"exp":"2026-08-21T13:00:00Z"}`,
			wantErr: errNoIssuedAt,
		},
		{
			name:    "explicit zero iat",
			payload: `{"user":{"sub":"s1"},"exp":"2026-08-21T13:00:00Z","iat":0}`,
			wantErr: errNoIssuedAt,
		},
		{
			name:    "negative iat",
			payload: `{"user":{"sub":"s1"},"exp":"2026-08-21T13:00:00Z","iat":-1787313600}`,
			wantErr: errNoIssuedAt,
		},
		{
			name:    "present iat",
			payload: `{"user":{"sub":"s1"},"exp":"2026-08-21T13:00:00Z","iat":1787313600}`,
			wantErr: nil,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := cookieAuth(testCookieKey)
			a.now = func() time.Time { return mint }
			cookie := &http.Cookie{
				Name:  a.sessionName(),
				Value: a.sign(purposeSession, []byte(c.payload)),
			}
			s, err := a.sessionFromRequestAt(requestWithCookie(cookie), mint)
			if !errors.Is(err, c.wantErr) {
				t.Fatalf("sessionFromRequestAt err = %v, want %v", err, c.wantErr)
			}
			u := s.User
			if c.wantErr == nil && u.Sub != "s1" {
				t.Errorf("user = %+v, want sub s1", u)
			}
		})
	}
}

// TestSessionFutureIssuedAtTolerated pins the clock-skew rule: the
// HMAC proves the library minted the cookie, so an IssuedAt ahead of
// the verifying instance's clock can only be skew between instances,
// and it must never lock the user out. The max lifetime just lands
// later by the skew.
func TestSessionFutureIssuedAtTolerated(t *testing.T) {
	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)

	cases := []struct {
		name string
		skew time.Duration
	}{
		{name: "no skew", skew: 0},
		{name: "seconds ahead", skew: 30 * time.Second},
		{name: "hours ahead", skew: 6 * time.Hour},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := cookieAuth(testCookieKey)
			mint := now.Add(c.skew)
			a.now = func() time.Time { return mint }

			rr := httptest.NewRecorder()
			a.setSessionCookie(rr, User{Sub: "s1"})
			cookie := recordedCookie(t, rr, a.sessionName())

			s, err := a.sessionFromRequestAt(requestWithCookie(cookie), now)
			if err != nil {
				t.Fatalf("cookie issued %v ahead rejected: %v", c.skew, err)
			}
			want := mint.Truncate(time.Second).Add(a.maxSessionLifetime)
			if got := a.maxLifetimeDeadline(s); !got.Equal(want) {
				t.Errorf("maxLifetimeDeadline = %v, want %v", got, want)
			}
		})
	}
}

// TestFreshSessionCookieAccepted is the positive control for the
// IssuedAt gate: a cookie minted by the library itself verifies.
func TestFreshSessionCookieAccepted(t *testing.T) {
	a := cookieAuth(testCookieKey)
	mint := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	a.now = func() time.Time { return mint }

	rr := httptest.NewRecorder()
	a.setSessionCookie(rr, User{Sub: "s1"})
	c := recordedCookie(t, rr, a.sessionName())

	if _, err := a.sessionFromRequestAt(requestWithCookie(c), mint); err != nil {
		t.Fatalf("freshly minted cookie rejected: %v", err)
	}
}

// TestSessionIssuedAtTamperDetected re-signs a payload whose "iat" was
// edited: the HMAC covers the whole payload, so an attacker who cannot
// forge it cannot backdate or advance the issue time either.
func TestSessionIssuedAtTamperDetected(t *testing.T) {
	a := cookieAuth(testCookieKey)
	mint := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	a.now = func() time.Time { return mint }

	rr := httptest.NewRecorder()
	a.setSessionCookie(rr, User{Sub: "s1"})
	c := recordedCookie(t, rr, a.sessionName())

	payload, err := a.verify(purposeSession, c.Value)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	var s sessionPayload
	if err := json.Unmarshal(payload, &s); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	s.IssuedAt = mint.Add(-365 * 24 * time.Hour).Unix()
	tampered, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	// Splice the edited payload in under the ORIGINAL signature.
	forged := *c
	forged.Value = base64.RawURLEncoding.EncodeToString(tampered) + c.Value[strings.Index(c.Value, "."):]
	if _, err := a.sessionFromRequestAt(requestWithCookie(&forged), mint); !errors.Is(err, errBadSignature) {
		t.Errorf("tampered iat: err = %v, want errBadSignature", err)
	}
}

// TestCookieRejectionReasonsWrapErrBadCookie keeps the reason
// sentinels a single external behavior: whatever fails, callers see
// errBadCookie.
func TestCookieRejectionReasonsWrapErrBadCookie(t *testing.T) {
	for _, err := range []error{errNoCookie, errBadSignature, errMalformedPayload, errCorruptPayload, errExpired, errNoIssuedAt} {
		if !errors.Is(err, errBadCookie) {
			t.Errorf("%v does not wrap errBadCookie", err)
		}
	}
}

func TestWithLoggerRejectsNil(t *testing.T) {
	a := cookieAuth(testCookieKey)
	if err := WithLogger(nil)(a); err == nil {
		t.Error("WithLogger(nil) accepted")
	}
	if err := WithLogger(slog.New(slog.DiscardHandler))(a); err != nil {
		t.Errorf("WithLogger: %v", err)
	}
}

// TestRenewSessionCookieWindow pins the renewal trigger to the renew
// window: a request renews only once it lands within renewWindow of the
// cookie's expiry. The default case is the default window, spelled
// out rather than derived.
func TestRenewSessionCookieWindow(t *testing.T) {
	issued := time.Date(2026, 8, 21, 0, 0, 0, 0, time.UTC)

	cases := []struct {
		name        string
		lifetime    time.Duration
		renewWindow time.Duration
		elapsed     time.Duration // since the cookie was written
		wantRenew   bool
	}{
		{"default window, just outside the renew window", 90 * 24 * time.Hour, 45 * 24 * time.Hour, 45*24*time.Hour - time.Second, false},
		{"default window, at the renew window boundary", 90 * 24 * time.Hour, 45 * 24 * time.Hour, 45 * 24 * time.Hour, true},
		{"custom window, just before its boundary", 90 * 24 * time.Hour, 24 * time.Hour, 89*24*time.Hour - time.Second, false},
		{"custom window, at its boundary", 90 * 24 * time.Hour, 24 * time.Hour, 89 * 24 * time.Hour, true},
		{"window == lifetime, one second in", 90 * 24 * time.Hour, 90 * 24 * time.Hour, time.Second, true},
		{"window == lifetime, mid-life", 90 * 24 * time.Hour, 90 * 24 * time.Hour, 30 * 24 * time.Hour, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := cookieAuth(testCookieKey)
			a.sessionLifetime = tc.lifetime
			a.renewWindow = tc.renewWindow
			a.maxSessionLifetime = 365 * 24 * time.Hour

			s := sessionPayload{
				User:     User{Sub: "s1"},
				IssuedAt: issued.Unix(),
				Expiry:   issued.Add(tc.lifetime),
			}
			now := issued.Add(tc.elapsed)

			rr := httptest.NewRecorder()
			a.renewSessionCookie(rr, s, now)
			var got bool
			for _, c := range rr.Result().Cookies() {
				if c.Name == a.sessionName() {
					got = true
				}
			}
			if got != tc.wantRenew {
				t.Errorf("renewed = %v, want %v", got, tc.wantRenew)
			}
		})
	}
}

// TestMintedSessionSurvivesSubSecondClock guards the whole-second
// validation from the other side: with a clock carrying nanoseconds, a
// freshly minted cookie at the shortest accepted lifetime must still
// verify rather than truncate itself into the past.
func TestMintedSessionSurvivesSubSecondClock(t *testing.T) {
	a := authWithLoginPath()
	a.sessionLifetime = time.Second
	a.renewWindow = time.Second
	a.maxSessionLifetime = 2 * time.Second
	at := time.Date(2026, 8, 21, 0, 0, 0, 999999999, time.UTC)
	a.now = func() time.Time { return at }

	rr := httptest.NewRecorder()
	a.setSessionCookie(rr, User{Sub: "s1"})
	c := recordedCookie(t, rr, a.sessionName())

	req := httptest.NewRequest(http.MethodGet, "/page", nil)
	req.AddCookie(c)
	if _, err := a.sessionFromRequestAt(req, at); err != nil {
		t.Fatalf("freshly minted session rejected at a sub-second clock: %v", err)
	}
}

// TestHostCookiePrefix pins the wire names: with secure cookies both
// the session and state cookies carry the "__Host-" prefix, and the
// read and clear paths use the same name they wrote.
func TestHostCookiePrefix(t *testing.T) {
	for _, tc := range []struct {
		name        string
		secure      bool
		wantSession string
		wantState   string
	}{
		{"secure", true, "__Host-_oidcauth", "__Host-_oidcauth_state"},
		{"http dev", false, "_oidcauth", "_oidcauth_state"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := cookieAuth(testCookieKey)
			a.secureCookies = tc.secure

			rr := httptest.NewRecorder()
			a.setSessionCookie(rr, User{Sub: "s1"})
			a.setStateCookie(rr, statePayload{State: "s", Nonce: "n"})
			sess := recordedCookie(t, rr, tc.wantSession)
			recordedCookie(t, rr, tc.wantState)

			if _, err := a.sessionFromRequestAt(requestWithCookie(sess), a.now()); err != nil {
				t.Errorf("sessionFromRequestAt: %v", err)
			}

			rr = httptest.NewRecorder()
			a.clearSessionCookie(rr)
			a.clearStateCookie(rr)
			if got := recordedCookie(t, rr, tc.wantSession); got.Value != "" {
				t.Errorf("cleared session cookie value = %q, want empty", got.Value)
			}
			if got := recordedCookie(t, rr, tc.wantState); got.Value != "" {
				t.Errorf("cleared state cookie value = %q, want empty", got.Value)
			}
		})
	}
}

// TestHostPrefixedSessionIgnoresBareName guards the read path: under
// secure cookies a cookie sent under the unprefixed name is not a
// session, so a subdomain cannot shadow one.
func TestHostPrefixedSessionIgnoresBareName(t *testing.T) {
	a := cookieAuth(testCookieKey)
	rr := httptest.NewRecorder()
	a.setSessionCookie(rr, User{Sub: "s1"})
	c := recordedCookie(t, rr, a.sessionName())

	bare := *c
	bare.Name = a.sessionCookieName
	if _, err := a.sessionFromRequestAt(requestWithCookie(&bare), a.now()); !errors.Is(err, errNoCookie) {
		t.Errorf("err = %v, want %v", err, errNoCookie)
	}
}

// TestCookieMaxAge pins Max-Age on every cookie this package writes:
// it must agree with Expires, and deletions must carry MaxAge < 0
// (net/http encodes that as "Max-Age=0") alongside a past Expires.
func TestCookieMaxAge(t *testing.T) {
	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	a := cookieAuth(testCookieKey)
	a.now = func() time.Time { return now }

	// A renewal clamped to the max lifetime is the only write where
	// Max-Age and Expires can disagree: exp is pinned to the
	// whole-second deadline while now carries a fraction. Put the
	// deadline 300ms out, close enough that rounding would have
	// produced Max-Age=0 and dropped the attribute.
	clampNow := now.Add(-300 * time.Millisecond)
	clampIssuedAt := now.Add(-a.maxSessionLifetime).Unix()

	writes := map[string]struct {
		write       func(w http.ResponseWriter)
		name        string
		wantMaxAge  int
		wantExpires time.Time // zero means now.Add(wantMaxAge seconds)
	}{
		"session set":   {func(w http.ResponseWriter) { a.setSessionCookie(w, User{Sub: "s1"}) }, a.sessionName(), int(a.sessionLifetime / time.Second), time.Time{}},
		"session clear": {a.clearSessionCookie, a.sessionName(), -1, time.Time{}},
		"state set": {func(w http.ResponseWriter) {
			a.setStateCookie(w, statePayload{State: "s", Nonce: "n"})
		}, a.stateCookieName(), int(stateTTL / time.Second), time.Time{}},
		"state clear": {a.clearStateCookie, a.stateCookieName(), -1, time.Time{}},
		"renewal": {func(w http.ResponseWriter) {
			a.renewSessionCookie(w, sessionPayload{
				User:     User{Sub: "s1"},
				Expiry:   now.Add(time.Minute),
				IssuedAt: now.Add(-time.Hour).Unix(),
			}, now)
		}, a.sessionName(), int(a.sessionLifetime / time.Second), time.Time{}},
		"renewal clamped to max lifetime": {func(w http.ResponseWriter) {
			a.renewSessionCookie(w, sessionPayload{
				User: User{Sub: "s1"},
				// Just short of the deadline, so the clamped expiry is
				// still an advance and the renewal is not skipped.
				Expiry:   clampNow.Add(200 * time.Millisecond),
				IssuedAt: clampIssuedAt,
			}, clampNow)
		}, a.sessionName(), 1, now},
	}
	for name, tc := range writes {
		t.Run(name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			tc.write(rr)
			c := recordedCookie(t, rr, tc.name)
			if c.MaxAge != tc.wantMaxAge {
				t.Errorf("MaxAge = %d, want %d", c.MaxAge, tc.wantMaxAge)
			}
			// Expires must say the same thing as Max-Age, so a client
			// honoring either one behaves identically.
			wantExpires := tc.wantExpires
			switch {
			case !wantExpires.IsZero():
			case tc.wantMaxAge < 0:
				wantExpires = expiredCookieTime
			default:
				wantExpires = now.Add(time.Duration(tc.wantMaxAge) * time.Second)
			}
			if !c.Expires.Equal(wantExpires) {
				t.Errorf("Expires = %v, want %v", c.Expires, wantExpires)
			}
		})
	}
}

// testRetiredKey is the pre-rotation secret in the key-ring tests;
// testCookieKey plays the freshly rotated-in one.
const testRetiredKey = "fedcba9876543210fedcba9876543210" // 32 bytes

// testOlderRetiredKey is the secret retired one rotation before
// testRetiredKey, so it lands at ring index 2.
const testOlderRetiredKey = "89abcdef0123456789abcdef01234567" // 32 bytes

// testForeignKey is in no position of any ring under test.
const testForeignKey = "00112233445566770011223344556677" // 32 bytes

func TestSessionCookieVerifiesAcrossKeyRotation(t *testing.T) {
	signedWith := func(secret string) *http.Cookie {
		signer := cookieAuth(secret)
		rr := httptest.NewRecorder()
		signer.setSessionCookie(rr, User{Sub: "s1"})
		return recordedCookie(t, rr, signer.sessionName())
	}

	cases := []struct {
		name    string
		cookie  *http.Cookie
		auth    *Auth
		wantErr bool
	}{
		{name: "old key still in the ring", cookie: signedWith(testRetiredKey),
			auth: cookieAuth(testCookieKey, testRetiredKey)},
		// Index 2 exercises the tail of the verify list, which an
		// off-by-one or a truncated ring would never reach.
		{name: "second previous key in the ring", cookie: signedWith(testOlderRetiredKey),
			auth: cookieAuth(testCookieKey, testRetiredKey, testOlderRetiredKey)},
		{name: "old key retired", cookie: signedWith(testRetiredKey),
			auth: cookieAuth(testCookieKey), wantErr: true},
		// A multi-key ring must still reject. This is the case that
		// catches an accumulator that accepts unconditionally rather
		// than only when some key matched.
		{name: "key in no position of the ring", cookie: signedWith(testForeignKey),
			auth: cookieAuth(testCookieKey, testRetiredKey, testOlderRetiredKey), wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.auth.sessionFromRequestAt(requestWithCookie(tc.cookie), tc.auth.now())
			if tc.wantErr {
				if !errors.Is(err, errBadSignature) {
					t.Errorf("err = %v, want bad signature", err)
				}
				return
			}
			if err != nil {
				t.Errorf("sessionFromRequestAt: %v", err)
			}
		})
	}
}

// A session minted before rotation must survive retirement of the key
// that minted it, provided it renewed while that key was still in the
// ring: renewal signs with the current key, not the one on the cookie.
func TestRenewalReSignsWithCurrentSecret(t *testing.T) {
	start := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	old := cookieAuth(testRetiredKey)
	old.now = func() time.Time { return start }
	rr := httptest.NewRecorder()
	old.setSessionCookie(rr, User{Sub: "s1"})
	minted := recordedCookie(t, rr, old.sessionName())

	// Rotate, then land a request inside the renew window (lifetime 1h,
	// window 30m).
	rotated := cookieAuth(testCookieKey, testRetiredKey)
	now := start.Add(45 * time.Minute)
	rotated.now = func() time.Time { return now }
	s, err := rotated.sessionFromRequestAt(requestWithCookie(minted), now)
	if err != nil {
		t.Fatalf("sessionFromRequestAt: %v", err)
	}
	rr = httptest.NewRecorder()
	rotated.renewSessionCookie(rr, s, now)
	renewed := recordedCookie(t, rr, rotated.sessionName())

	retired := cookieAuth(testCookieKey)
	retired.now = func() time.Time { return now }
	if _, err := retired.sessionFromRequestAt(requestWithCookie(renewed), now); err != nil {
		t.Errorf("renewed cookie rejected after retiring the minting key: %v", err)
	}
}

func TestNewRejectsBadPreviousCookieSecret(t *testing.T) {
	cases := []struct {
		name     string
		previous []string
		wantErr  string
	}{
		{name: "too short", previous: []string{"short"}, wantErr: "32 bytes"},
		{name: "empty entry", previous: []string{testRetiredKey, ""}, wantErr: "empty entry"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New(Config{
				Issuer: "https://auth.example.com", ClientID: "app", ClientSecret: "s",
				RedirectURL: testRedirectURL, CookieSecret: testCookieKey,
				PreviousCookieSecrets: tc.previous,
			})
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("err = %v, want error containing %q", err, tc.wantErr)
			}
		})
	}
}

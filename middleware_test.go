package oidcauth

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
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
	c := recordedCookie(t, rr0, a.sessionCookieName)

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
	c := recordedCookie(t, rr0, a.sessionCookieName)

	a.now = func() time.Time { return time.Now().Add(a.sessionTTL + time.Minute) }
	var u User
	req := httptest.NewRequest(http.MethodGet, "/private", nil)
	req.AddCookie(c)
	rr := httptest.NewRecorder()
	a.RequireAuth(okHandler(t, &u)).ServeHTTP(rr, req)
	if rr.Code != http.StatusFound {
		t.Errorf("status = %d, want 302 redirect to login", rr.Code)
	}
}

func TestUserHelperOnPublicPage(t *testing.T) {
	a := authWithLoginPath()
	want := User{Sub: "s1"}
	rr0 := httptest.NewRecorder()
	a.setSessionCookie(rr0, want)
	c := recordedCookie(t, rr0, a.sessionCookieName)

	if _, ok := a.User(httptest.NewRequest(http.MethodGet, "/", nil)); ok {
		t.Errorf("User reported ok without a session")
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(c)
	if got, ok := a.User(req); !ok || !reflect.DeepEqual(got, want) {
		t.Errorf("User = (%+v, %v), want (%+v, true)", got, ok, want)
	}
}

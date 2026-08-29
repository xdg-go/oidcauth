# oidcauth

[![Go Reference](https://pkg.go.dev/badge/github.com/xdg-go/oidcauth.svg)](https://pkg.go.dev/github.com/xdg-go/oidcauth)

OIDC login for Go web apps using only `net/http`. oidcauth wraps
[go-oidc](https://github.com/coreos/go-oidc) and `golang.org/x/oauth2`
to run the authorization-code flow with PKCE, validate state and
nonce, and keep the verified identity in an HMAC-signed cookie. It
works with any conformant OIDC issuer.

What it is not: an OAuth client for calling APIs on the user's
behalf, a general session store, or a token-refresh manager. It logs
a user in and tells your handlers who they are.

## Install

```
go get github.com/xdg-go/oidcauth
```

## Quick start

```go
func main() {
	auth, err := oidcauth.NewFromEnv()
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	auth.Mount(mux) // /auth/login, /auth/callback, /auth/logout

	mux.Handle("/private", auth.RequireAuth(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user, _ := oidcauth.UserFromContext(r.Context())
			fmt.Fprintf(w, "hello %s (%s)", user.Name, user.Sub)
		})))

	log.Fatal(http.ListenAndServe(":8083", auth.Authenticate(mux)))
}
```

`NewFromEnv` reads:

| Variable | Meaning |
|---|---|
| `AUTH_ISSUER` | OIDC issuer URL, e.g. `https://auth.example.com` |
| `AUTH_CLIENT_ID` | OAuth2 client id |
| `AUTH_CLIENT_SECRET` | OAuth2 client secret |
| `AUTH_REDIRECT_URL` | Absolute callback URL, e.g. `https://app.example.com/auth/callback` |
| `AUTH_COOKIE_SECRET` | HMAC key for cookies, at least 32 bytes (`openssl rand -hex 32`) |
| `AUTH_COOKIE_SECRET_PREVIOUS` | Optional comma-separated list of retired keys that still verify cookies |

An `http://` redirect URL (local dev) turns off the cookie `Secure`
flag. Use `oidcauth.New(cfg, opts...)` to configure from code.

## Guide

### Protect routes

Wrap the whole tree in `Authenticate`: it verifies the cookie once
per request, never rejects, and keeps active sessions alive. Gate
individual routes with `RequireAuth`, which redirects anonymous GETs
to login and returns 401 to everything else. `UserFromContext` works
behind either, so public pages can show login/logout links.
See [Middleware](https://pkg.go.dev/github.com/xdg-go/oidcauth#hdr-Middleware).

### Identify the user

Key accounts on the pair `(user.Issuer, user.Sub)`, never on email.
`sub` is unique and never reassigned within an issuer; email is
mutable, reassignable, and in some issuers unverified. Store email
alongside the pair for display and recovery only. The rationale,
including the nOAuth attack class and issuer-migration caveats, is in
[Identity](https://pkg.go.dev/github.com/xdg-go/oidcauth#hdr-Identity).

### Log out

Logout is POST-only, so drive it from a form, not a link:

```html
<form method="post" action="/auth/logout"><button>Log out</button></form>
```

It clears the app's cookie; the issuer's own session is untouched. To
end a session from inside your own handler (account deletion, say),
call `auth.ClearSession(w)`.

### Tune session lifetime

Two clocks run on every session; the first to expire ends it. The
session lifetime slides with activity, the max lifetime does not.

```go
auth, err := oidcauth.NewFromEnv(
	oidcauth.WithSessionLifetime(30*24*time.Hour),    // slides with activity (default 90d)
	oidcauth.WithSessionRenewWindow(15*24*time.Hour), // renew this close to expiry (default 45d)
	oidcauth.WithSessionMaxLifetime(90*24*time.Hour), // hard cap from login (default 365d)
)
```

`New` requires renew window <= lifetime <= max lifetime and fails
rather than substituting defaults.

Changing the session lifetime applies only to cookies minted or
renewed afterward, because the expiry is baked in at write time.
Changing the max lifetime applies retroactively: it is measured from
the issue time stored in each cookie.

Renewal extends the cookie; it does not re-authenticate. Claims freeze
at login, so a user disabled at the provider -- or a thief holding a
stolen cookie -- stays valid until the max lifetime. To end a session
sooner, see [Revoke a session](#revoke-a-session) below and
[Session lifetime](https://pkg.go.dev/github.com/xdg-go/oidcauth#hdr-Session_lifetime).

### Revoke a session

`WithRevokedBefore` asks you, on every verified session, for the
instant before which that user's sessions are void; the library
rejects any session issued before it. To log a user out everywhere,
store `time.Now()` for them when revoking and return it. The lookup
runs on every authenticated request, so keep it fast and
concurrency-safe; caching the cutoff is your job:

```go
auth, err := oidcauth.NewFromEnv(
	oidcauth.WithRevokedBefore(
		func(ctx context.Context, u oidcauth.User) (time.Time, error) {
			// a store miss returns the zero time, which revokes nothing
			cutoff, err := store.RevokedAt(ctx, u.Issuer, u.Sub)
			if err != nil {
				// outage, not a cutoff: 503 under RequireAuth,
				// never a renewal; under Authenticate the request
				// looks anonymous, so check
				// SessionUnavailableFromContext before treating it
				// as logged out
				return time.Time{}, err
			}
			return cutoff, nil
		}),
)
```

Store the revocation instant, never the current cookie's issue time: a
stolen cookie carries the same issue time as the user's own. Take that
instant from the clock the app serves requests on (the process's
`time.Now()`), not from the database's `NOW()`: a cutoff that lands in
a later second than the server's clock is treated as a lookup failure.
For the
reasoning, see
[Revoking sessions](https://pkg.go.dev/github.com/xdg-go/oidcauth#hdr-Revoking_sessions).

### Ask for consent once per new user

```go
oidcauth.ForceApprovalIfNewUser(func(iss, sub string) bool {
	return store.UserExists(iss, sub)
})
```

An unfamiliar `(iss, sub)` restarts the login with a forced consent
prompt, so every user sees the consent screen exactly once for your
app.

### Caching and CDNs

Any response that writes a session cookie gets
`Cache-Control: private, no-store`; any response with a verified
session gets `private`; anonymous responses are left alone, so public
pages stay cacheable. One rule: if your handler sets `Cache-Control`
itself on a route that can carry a session, set `private, no-store`.
A page whose body differs by login state -- a public page rendering
login/logout links, say -- must set `private, no-store` itself: the
anonymous rendering carries only `Vary: Cookie`, which CDNs do not
honor reliably.
See [Caching](https://pkg.go.dev/github.com/xdg-go/oidcauth#hdr-Caching).

### Cookies

Cookies are named `_oidcauth` and `_oidcauth_state` (`oidcauth.WithCookieName`
renames both). With `Secure` on they go on the wire as `__Host-_oidcauth` and
`__Host-_oidcauth_state`; the `__Host-` prefix stops a sibling subdomain from
shadowing them. For plain-http dev, where browsers would not honor it,
oidcauth uses the bare names.

To rotate cookie secrets, move the current secret into `PreviousCookieSecrets`
(or `AUTH_COOKIE_SECRET_PREVIOUS`), set a fresh `CookieSecret`, and deploy.
The new key signs every cookie; the old one still verifies, so nobody is
logged out.

## Status

Pre-1.0. The API is small and settling; breaking changes land on minor
versions until 1.0.

## License

Apache 2.0. See [LICENSE](LICENSE).

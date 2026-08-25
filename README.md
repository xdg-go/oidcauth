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

Cookies are named `_oidcauth` and `_oidcauth_state`
(`oidcauth.WithCookieName` renames both). With `Secure` on they go on
the wire as `__Host-_oidcauth` and `__Host-_oidcauth_state`; the
`__Host-` prefix stops a sibling subdomain from shadowing them, and
plain-http dev, where browsers would not honor it, uses the bare
names.

Upgrading to a version that adds the `__Host-` prefix logs every user
out once: the renamed cookie makes existing sessions invisible, and
the old bare-named cookie is ignored until it expires on its own. A
login that is mid-redirect when the new build starts fails its
callback and must be retried. This is a one-time break; reading both
names would undo the shadowing protection the prefix exists to
provide.

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

```go
auth, err := oidcauth.NewFromEnv(
	oidcauth.WithSessionLifetime(30*24*time.Hour),   // slides with activity
	oidcauth.WithSessionRenewWindow(15*24*time.Hour), // renew this close to expiry
	oidcauth.WithSessionMaxLifetime(90*24*time.Hour), // hard cap from login
)
```

Changing the session lifetime applies only to cookies minted or
renewed afterward, because the expiry is baked in at write time.
Changing the max lifetime applies retroactively: it is measured from
the issue time stored in each cookie.

Defaults are 90, 45, and 365 days. Renewal does not re-check the
identity provider, so the max lifetime bounds how long a disabled
user can stay logged in. See
[Session lifetime](https://pkg.go.dev/github.com/xdg-go/oidcauth#hdr-Session_lifetime).

### Rotating the cookie secret

Move the current secret into `PreviousCookieSecrets` (or
`AUTH_COOKIE_SECRET_PREVIOUS`), set a fresh `CookieSecret`, and deploy.
The new key signs every cookie; the old one still verifies, so nobody is
logged out and no login in mid-redirect breaks.

Retire the old key one full session lifetime after the last instance
still carrying it as the *signing* key is gone -- a staggered rollout or
a rollback keeps minting old-key cookies, so the clock starts at the end
of the rollout, not the start of the deploy. One lifetime is enough
because a cookie signed at or before that moment carries an expiry no
later than its signing time plus the session lifetime, so every cookie
the old key can still verify has expired by then.

Rotation is not revocation. Cookies signed by the old key stay valid for
as long as it stays in the ring. Dropping it immediately instead of a
lifetime later is the logout-everyone kill switch, and is the only
in-band one until per-session issue time is exposed to applications.

The ring is uncapped, and an unauthenticated request carrying a garbage
cookie costs one HMAC per key, so a long ring is a work multiplier an
attacker can lean on. How long a ring to carry is your call.

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
See [Caching](https://pkg.go.dev/github.com/xdg-go/oidcauth#hdr-Caching).

## Status

Pre-1.0. The API is small and settling; breaking changes land on minor
versions until 1.0.

## License

Apache 2.0. See [LICENSE](LICENSE).

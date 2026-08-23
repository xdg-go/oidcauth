# oidcauth: Sliding Session Renewal with a Max Lifetime

Copy this file to the `oidcauth` repo and work it there. It carries the
library half of the session-lifetime roadmap: add `IssuedAt` to the
session payload, slide the session lifetime on the verify path, bound
the total lifetime, and expose issue time to applications. The skeleton
half (per-user revocation epoch) lives in the template repo and depends
on the release this plan produces.

Target end state for apps: a 90d session lifetime with sliding renewal,
a 1y max lifetime, and enough exposed session metadata for an app to reject
sessions issued before a per-user revocation timestamp.

## Testing Philosophy

- **Automated tests for session logic**: payload marshal/unmarshal,
  signature verification, expiry math, renewal thresholds, and the
  max-lifetime refusal. This is security-relevant code -- every branch
  gets a test.
- **Table-driven clock tests**: inject a clock (or a time function)
  rather than sleeping. No test should take longer than the code under
  test.
- **Fail closed, always**: a payload missing `IssuedAt` must be
  rejected, never accepted with a zero issue time.
- **Handler tests**: `net/http/httptest` round-trips through the real
  middleware, asserting `Set-Cookie` presence or absence.
- **No live IdP in unit tests**: keep the existing fake/mock issuer
  seam; only end-to-end tests may touch dex.

## Verification Checklist

Before marking a phase complete and committing it:

1. `go vet ./...` clean
2. `go test ./...` passes, including `-race`
3. Exported API changes reflected in doc comments and README
4. No new dependencies

When verification of a phase or subphase is complete, commit all
relevant newly-created and modified files.

## Dependencies Between Phases

```
Phase 1 (Survey)
       │
       ▼
Phase 2 (IssuedAt in payload, fail closed)
       │
       ├─► Phase 3 (Sliding renewal + max lifetime)
       │            │
       │            ▼
       └─────► Phase 4 (Expose IssuedAt to apps)
                     │
                     ▼
              Phase 5 (Docs + release)
```

---

## Phase 1: Survey Current Behavior

Establish what exists before changing it.

### 1.1 Map the session code path
- [x] Locate `sessionPayload`, its encode/decode helpers, the HMAC
      signing/verification code, and the middleware that reads the
      cookie
- [x] Write down the current defaults: 24h absolute TTL, cookie name,
      cookie attributes (Secure, HttpOnly, SameSite, Path, Max-Age)
- [x] Note every configuration knob an app can set today
      (`WithSessionTTL` or equivalent) and which are exported

### 1.2 Characterize expiry
- [x] **Test**: accept just before `Expiry`, reject at it and after

### 1.3 Introduce a test clock
- [x] Route every `time.Now()` in the session path through an
      injectable clock field (unexported, defaulting to `time.Now`)
- [x] **Test**: existing expiry tests pass using the injected clock
      instead of real time

---

## Phase 2: Add `IssuedAt` to the Session Payload

Sliding renewal needs two clocks. Without an issue time, a stolen
cookie renews forever.

### 2.1 Extend the payload
- [x] Add `IssuedAt` to `sessionPayload`; set it at mint time
- [x] **Test**: marshal/unmarshal round-trip preserves `IssuedAt` to
      the intended precision (store as Unix seconds; document it)
- [x] Pin the zero-value check: a zero `time.Time` is
      `0001-01-01T00:00:00Z`, whose `Unix()` is a large negative number.
      Test the check that actually ships, whichever encoding wins

### 2.2 Fail closed on old cookies
- [x] Reject any payload lacking `IssuedAt` (zero value) with the same
      code path as an invalid signature -- no partial trust
- [x] Add a logging seam: the library has no logger today and
      `errBadCookie` is a single opaque value. Decide `WithLogger(*slog.Logger)`
      plus distinct sentinel errors before writing the rejection path
- [x] Log the rejection at debug with a distinguishing reason so a
      spike in re-logins is explainable
- [x] **Test**: a payload with no `iat` field is rejected
- [x] **Test**: a freshly minted cookie is accepted
- [x] **Test**: a cookie with a valid signature but tampered `IssuedAt`
      is rejected (signature covers the whole payload)

---

## Phase 3: Sliding Renewal and Max Lifetime

Two deadlines: a session lifetime that slides under an `Authenticate`
mount, and a max lifetime that does not.

### 3.1 Configuration surface
- [x] Add session-lifetime and max-lifetime options (names and defaults
      decided here; recommended library defaults: 90d lifetime, 1y max)
- [x] Validate at construction: max must not be less than the session
      lifetime; a non-positive value is a config error, not a silent
      default
- [x] Keep the single-TTL behavior reachable (max == session lifetime)
- [x] **Test**: construction rejects max < session lifetime
- [x] Name the middleware `Authenticate` (renews) and
      `AuthenticateNoRenew` (verifies only); `RequireAuth` composes on
      `Authenticate`; delete `Auth.User(r)`
- [x] `Authenticate` always stores a context sentinel, even for
      anonymous requests, so "middleware never ran" is distinguishable
      from "not logged in"
- [x] `RequireAuth` verifies inline when the sentinel is absent, so both
      `Authenticate(mux)` + `RequireAuth` and bare `RequireAuth` are
      correct with exactly one verification
- [x] **Test**: bare `RequireAuth` (no outer `Authenticate`) still
      authenticates, and does not verify twice when wrapped

### 3.2 Renewal in the verify path
- [x] Re-issue the cookie when now is past `Expiry - sessionLifetime/2`
      (half-life of the session lifetime), preserving the original
      `IssuedAt`
- [x] Refuse renewal -- and reject the request -- once now is past
      `IssuedAt + maxSessionLifetime`, even if the session lifetime has
      not lapsed
- [x] Renewal writes `Set-Cookie` at middleware entry, before calling
      the next handler, so it cannot lose a race with the handler's own
      headers (see 3.4)
- [x] **Test**: fresh cookie, no renewal, no `Set-Cookie`
- [x] **Test**: just past half-life, renewed, new `Expiry`, same
      `IssuedAt`
- [x] **Test**: past session lifetime, rejected
- [x] **Test**: within session lifetime but past max lifetime, rejected and
      not renewed
- [x] **Test**: renewal on a request whose handler writes a response
      body -- cookie still lands
- [x] Clamp a renewed `Expires` to `IssuedAt + maxSessionLifetime` so the cookie
      never advertises a lifetime the server will refuse to honor
- [x] Suppress the duplicate `Set-Cookie` when renewal races a mint or a
      clear: `setSessionCookie` and `clearSessionCookie` must drop any
      pending same-name `Set-Cookie` from `w.Header()` before writing
- [x] **Test**: logout past the renewal half-life emits exactly one
      `Set-Cookie` for the session cookie, and it is the clearing one
- [x] **Test**: the callback path past half-life likewise emits one

### 3.3 Concurrency and races
- [x] **Test**: `-race` over concurrent requests carrying the same
      cookie; renewal must not corrupt shared state
- [x] Confirm renewal is not attempted on requests where the session is
      absent or already invalid

### 3.4 Cache safety

A response carrying a session cookie carries a credential. This is not
theoretical: RFC 9111 §7.3 states that `Set-Cookie` does not inhibit
caching, and AWS CloudFront documents that it caches `Set-Cookie` and
"sends those `Set-Cookie` headers to viewers on all cache hits."
nginx, Varnish, and Fastly refuse such responses by default; Cloudflare
under "Cache Everything" with an edge TTL strips the `Set-Cookie` and
caches the body, which breaks login instead of leaking it. Explicit
cache headers are load-bearing, not belt-and-braces.

Write the headers at middleware entry, before calling the next handler.
Renewal depends only on the incoming cookie and the clock, so nothing
has to wait for the handler to run -- and 3.2 already requires the
`Set-Cookie` to precede the handler's headers. No `ResponseWriter`
wrapper. (Prior art: oauth2-proxy's `refreshSessionIfNeeded` writes
straight to the real writer; `alexedwards/scs` needs a wrapper only
because its session data is mutated by the handler.)

- [x] Set `Cache-Control: private, no-store` on every response where the
      library writes a session cookie: renewal, callback, and logout
- [x] Set `Cache-Control: private` when a valid session is found but no
      cookie is written (both `Authenticate` and `AuthenticateNoRenew`)
- [x] Leave `Cache-Control` untouched on anonymous requests, so public
      pages stay shared-cacheable
- [x] Add `Vary: Cookie` unconditionally at middleware entry (see the
      decision log; one `Header().Add`, no branch)
- [x] Document that a handler which overwrites `Cache-Control` on a
      renewed response defeats this, and that the library does not
      prevent it
- [x] **Test**: a renewed response carries `private, no-store`
- [x] **Test**: a valid session with no renewal carries `private` and no
      `no-store`
- [x] **Test**: an anonymous request leaves a handler-set
      `Cache-Control: public` intact
- [x] **Test**: `Vary: Cookie` present on all of the above

**Bug (found in comment review, fixed):** in
`Authenticate(AuthenticateNoRenew(h))` with a session past its
half-life, the outer mount renews and sets `private, no-store`, then
the inner mount takes the sentinel branch and calls
`markPrivateResponse`, whose `Set` downgrades the header back to
`private`. A response carrying a renewed session cookie is then
storable by a private cache. The fresh-verify path orders
`markPrivateResponse` before renewal and is unaffected; only the
sentinel-hit branch in `Auth.authenticate` reverses that order.

- [x] Fix the downgrade: skip `markPrivateResponse` on the sentinel-hit
      path once a renewal has been recorded, or make it non-downgrading
      rather than an unconditional `Set`
- [x] **Test**: `Authenticate(AuthenticateNoRenew(h))` past the
      half-life carries `private, no-store`.
      `TestNoRenewInsideRenewingStillOneCookie` covers this nesting but
      only counts `Set-Cookie`, so it cannot see the downgrade

### 3.5 Cookie attributes

- [ ] Use the `__Host-` cookie name prefix when `secureCookies` is true.
      Per draft-ietf-httpbis-rfc6265bis-22 §5.7 the browser stores such
      a cookie only when it is `Secure`, host-only, and `Path=/`; the
      real requirement is host-only, and omitting `Domain` is how you
      get it. Path is already `/` with no Domain, so this blocks
      subdomain cookie shadowing
- [ ] Set `Max-Age` alongside `Expires`. rfc6265bis §4.1.2.2: "If a
      cookie has both the Max-Age and the Expires attribute, the Max-Age
      attribute has precedence." `Max-Age` is relative and so immune to
      client clock skew; keep `Expires` for ancient clients
- [ ] Decide the clock-skew rule for `IssuedAt` in the future across
      instances (the MAC means skew is the only cause) and document it
- [ ] Document that a session-lifetime change applies only to cookies
      minted or renewed afterward; the max lifetime, keyed on stored
      `IssuedAt`, does apply retroactively

### 3.6 Cookie secret key ring

Today `Config.CookieSecret` is a single HMAC key used for both the
session and state cookies, so rotating it logs out every user at once
and breaks any login mid-redirect. That makes the only global kill
switch too expensive to rehearse.

- [ ] Add `Config.PreviousCookieSecrets []string`, verify-only. Keep
      `CookieSecret` as the one that signs, so "which key signs" is never
      ambiguous
- [ ] `FromEnv` reads `AUTH_COOKIE_SECRET_PREVIOUS` as a comma-separated
      list; absent is fine, unlike the required `AUTH_COOKIE_SECRET`
- [ ] Replace `a.cookieSecret` with a signing key plus an ordered verify
      list; `sign` uses the signing key, `verify` tries each in turn with
      `subtle.ConstantTimeCompare`. Both cookie purposes get this for
      free -- `sign`/`verify` are already purpose-scoped and shared
- [ ] Validate each entry at construction with the existing 32-byte rule,
      and reject empty entries rather than skipping them
- [ ] Do not cap the ring size. Document the cost instead: an
      unauthenticated request with a garbage cookie costs one HMAC per
      key, so a long ring is a work multiplier an attacker can lean on.
      Keeping it short is the operator's call, not the library's
- [ ] Document the rotation procedure: move the current secret into
      `PreviousCookieSecrets`, set a fresh `CookieSecret`, deploy. Retire
      the old key one full session lifetime later -- by then every live
      session has renewed at least once and been re-signed, and a session
      idle for almost the whole lifetime is the worst case that still needs
      the old key
- [ ] Document that rotation is *not* revocation. Old cookies stay valid
      until the old key is retired; dropping it immediately is the
      logout-everyone kill switch, and is the only in-band one until
      Phase 4 lands
- [ ] **Test**: a cookie signed with a previous secret verifies; the same
      cookie fails once that secret leaves the ring
- [ ] **Test**: renewal re-signs with the current secret, so a renewed
      cookie survives retirement of the key that minted it
- [ ] **Test**: a state cookie minted before rotation still completes its
      callback after rotation
- [ ] **Test**: construction rejects a previous secret shorter than 32
      bytes

---

## Phase 4: Expose Issue Time to Applications

The skeleton's per-user revocation epoch needs to see `IssuedAt`.

### 4.1 Pick the exposure mechanism
- [ ] Choose between adding issue time to the context claims the app
      already reads and a `WithSessionValidator(func(User, issuedAt)
      bool)` hook. Prefer the validator hook if it lets the library
      reject before the handler runs; prefer context claims if the app
      would otherwise duplicate lookups
- [ ] Record the choice and the rejected alternative in the repo's
      decision log

### 4.2 Implement and test
- [ ] Implement the chosen mechanism
- [ ] Ensure a validator that returns false produces the same response
      as an expired session (no leaking why)
- [ ] Ensure a rejecting validator suppresses renewal
- [ ] **Test**: app-side rejection based on an issue time older than a
      threshold
- [ ] **Test**: validator not called when the cookie is absent or the
      signature is bad
- [ ] **Test**: default behavior unchanged when no validator is set
- [ ] Doc comment: "log out everywhere" sets the epoch to `now`, never
      to the current cookie's `IssuedAt`. A stolen cookie is a clone and
      shares that timestamp, so a strictly-before comparison spares the
      attacker along with the user; the user re-authenticates
- [ ] **Test**: an epoch equal to a live session's `IssuedAt` does not
      revoke it, and an epoch of `now` does

---

## Phase 5: Documentation and Release

### 5.1 Docs
- [ ] README: session lifetime model, the two clocks, the defaults, and
      how an app implements revocation on top of `IssuedAt`
- [ ] Doc comments on every new exported symbol
- [ ] Note explicitly that renewal keeps a stolen cookie alive only
      until the max lifetime, and that revocation is the app's job
- [ ] State that renewal is not re-authentication: claims freeze at
      login, so a user disabled at the IdP can stay valid until the max
      lifetime
- [ ] `AuthenticateNoRenew` doc comment warns that at least one renewing
      mount must sit in the user's regular path, or sessions expire a
      full lifetime after login regardless of activity
- [ ] Warn that a page rendering differently by login state must not be
      shared-cached, whichever middleware it is behind

### 5.2 Release
- [ ] Tag the release
- [ ] **Test**: build the skeleton against the tagged version before
      announcing it done -- that is the first real consumer

---

## Future Phases (Deferred)

n/a

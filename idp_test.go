package oidcauth

// A minimal in-process OIDC issuer for tests: discovery, JWKS, and a
// token endpoint minting RS256 ID tokens with test-controlled claims.
// JWS signing is hand-rolled (~30 lines) to avoid a direct jose dep.

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

type fakeIDP struct {
	t   *testing.T
	srv *httptest.Server
	key *rsa.PrivateKey

	// claims overrides/extends the default ID token claims minted by
	// the token endpoint. Set "nonce" (and "aud" to test mismatches).
	claims map[string]any

	// lastTokenForm records the most recent token-endpoint request
	// form, e.g. to assert the PKCE code_verifier was sent.
	lastTokenForm url.Values

	// tokenStatus, when non-zero, makes the token endpoint respond with
	// that HTTP status instead of a token, simulating an exchange failure.
	tokenStatus int

	// omitIDToken, when true, makes the token endpoint return a
	// successful response with no id_token, simulating a broken issuer.
	omitIDToken bool
}

func newFakeIDP(t *testing.T) *fakeIDP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	idp := &fakeIDP{t: t, key: key, claims: map[string]any{}}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{
			"issuer":                                idp.srv.URL,
			"authorization_endpoint":                idp.srv.URL + "/auth",
			"token_endpoint":                        idp.srv.URL + "/token",
			"jwks_uri":                              idp.srv.URL + "/keys",
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{
			"keys": []map[string]any{{
				"kty": "RSA", "kid": "test", "alg": "RS256", "use": "sig",
				"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
				"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
			}},
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		idp.lastTokenForm = r.Form
		if idp.tokenStatus != 0 {
			http.Error(w, "token endpoint failure", idp.tokenStatus)
			return
		}
		resp := map[string]any{
			"access_token": "test-access-token",
			"token_type":   "bearer",
			"expires_in":   300,
		}
		if !idp.omitIDToken {
			resp["id_token"] = idp.mintIDToken()
		}
		writeJSON(w, resp)
	})

	idp.srv = httptest.NewServer(mux)
	t.Cleanup(idp.srv.Close)
	return idp
}

// mintIDToken signs an RS256 JWT with default claims merged with
// idp.claims.
func (idp *fakeIDP) mintIDToken() string {
	now := time.Now()
	claims := map[string]any{
		"iss":            idp.srv.URL,
		"sub":            "test-sub-1",
		"aud":            testClientID,
		"exp":            now.Add(5 * time.Minute).Unix(),
		"iat":            now.Unix(),
		"email":          "user@example.com",
		"email_verified": true,
		"name":           "Test User",
	}
	for k, v := range idp.claims {
		claims[k] = v
	}
	header := map[string]any{"alg": "RS256", "kid": "test"}
	signingInput := b64JSON(idp.t, header) + "." + b64JSON(idp.t, claims)
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, idp.key, crypto.SHA256, digest[:])
	if err != nil {
		idp.t.Fatalf("sign id token: %v", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func b64JSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		panic(fmt.Sprintf("encode json: %v", err))
	}
}

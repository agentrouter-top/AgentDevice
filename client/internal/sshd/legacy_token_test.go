package sshd

// LEGACY: tests of the token password (legacy_token.go); delete with it (AgentHost#385, AgentDevice#253).

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	gossh "golang.org/x/crypto/ssh"

	"github.com/agentrouter-top/AgentDevice/client/internal/identity"
)

// The token tests sign with identity/v1's published TEST-ONLY key.
const testIssuer = "https://newapi.test"

var vectors = filepath.Join("..", "..", "testdata", "contracts", "agentidentity", "contracts", "identity", "v1", "vectors")

func testKey(t *testing.T) (*ecdsa.PrivateKey, identity.StaticKeys) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(vectors, "TEST-ONLY-private-keys.json"))
	if err != nil {
		t.Fatal(err)
	}
	var set struct {
		Keys []struct{ Kid, X, Y, D string } `json:"keys"`
	}
	if err := json.Unmarshal(raw, &set); err != nil {
		t.Fatal(err)
	}
	k := set.Keys[0]
	dec := func(s string) *big.Int {
		b, err := base64.RawURLEncoding.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return new(big.Int).SetBytes(b)
	}
	priv := &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: elliptic.P256(), X: dec(k.X), Y: dec(k.Y)}, D: dec(k.D)}
	jwks, err := os.ReadFile(filepath.Join(vectors, "TEST-ONLY-jwks.json"))
	if err != nil {
		t.Fatal(err)
	}
	keys, err := identity.ParseJWKS(jwks)
	if err != nil {
		t.Fatal(err)
	}
	if k.Kid != "test-2026-11-a" {
		t.Fatalf("first test key is %s", k.Kid)
	}
	return priv, keys
}

type claims map[string]any

func mint(t *testing.T, priv *ecdsa.PrivateKey, edit func(claims)) string {
	t.Helper()
	now := time.Now().Unix()
	c := claims{
		"iss": testIssuer, "sub": "svc_agenthost", "ten": "acc_1001", "own": testOwner, "pay": testOwner,
		"aud": "netbird", "scp": []string{"computer:" + testComputer + ":ssh"}, "run": "cnv_test1",
		"iat": now, "exp": now + 600, "jti": "0b6f2c1e-6a51-4c7e-9a43-1f0f6b9d2a01",
	}
	if edit != nil {
		edit(c)
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims(c))
	tok.Header["typ"] = "at+jwt"
	tok.Header["kid"] = "test-2026-11-a"
	s, err := tok.SignedString(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// startLegacy runs the server with the former token password as well.
func startLegacy(t *testing.T) (*harness, *ecdsa.PrivateKey) {
	t.Helper()
	priv, keys := testKey(t)
	h := startWith(t, func(c *Config) {
		c.Authorizer = &Authorizer{
			Verifier:   &identity.Verifier{Issuer: testIssuer, Keys: keys},
			ComputerID: testComputer, Own: testOwner, Ten: testTenant, MaxAge: 600 * time.Second,
		}
	})
	return h, priv
}

func (h *harness) dial(t *testing.T, token string) (*gossh.Client, error) {
	t.Helper()
	return h.dialWith(t, gossh.Password(token))
}

func TestAuthAcceptsOnlyThisDevicesOwnerWithTheSSHScope(t *testing.T) {
	h, priv := startLegacy(t)
	if _, err := h.dial(t, mint(t, priv, nil)); err != nil {
		t.Fatalf("valid token refused: %v", err)
	}
	cases := map[string]func(claims){
		"another owner":    func(c claims) { c["own"] = "acc_9999" },
		"another tenant":   func(c claims) { c["ten"] = "acc_9998" },
		"another computer": func(c claims) { c["scp"] = []string{"computer:cmp_other:ssh"} },
		"another right":    func(c claims) { c["scp"] = []string{"computer:" + testComputer + ":read"} },
		"another audience": func(c claims) { c["aud"] = "agentcompute" },
		"another issuer":   func(c claims) { c["iss"] = "https://other.test" },
		"too old to connect": func(c claims) {
			old := time.Now().Add(-11 * time.Minute).Unix()
			c["iat"], c["exp"] = old, old+3000
			delete(c, "run")
		},
		"expired": func(c claims) {
			old := time.Now().Add(-20 * time.Minute).Unix()
			c["iat"], c["exp"] = old, old+600
		},
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			if c, err := h.dial(t, mint(t, priv, edit)); err == nil {
				c.Close()
				t.Fatal("accepted")
			}
		})
	}
	if c, err := h.dial(t, "not-a-token"); err == nil {
		c.Close()
		t.Fatal("accepted garbage")
	}
	// A wildcard computer scope of the same owner is a valid ceiling.
	if c, err := h.dial(t, mint(t, priv, func(c claims) { c["scp"] = []string{"computer:*:ssh"} })); err != nil {
		t.Fatalf("computer:*:ssh refused: %v", err)
	} else {
		c.Close()
	}
}

// Without an Authorizer the server takes no password at all.
func TestNoTokenPasswordWithoutTheLegacyAuthorizer(t *testing.T) {
	priv, _ := testKey(t)
	h := start(t)
	if c, err := h.dial(t, mint(t, priv, nil)); err == nil {
		c.Close()
		t.Fatal("a token password was accepted without the legacy Authorizer")
	}
}

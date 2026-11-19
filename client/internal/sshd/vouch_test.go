package sshd

import (
	"crypto/rand"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"
)

// A plain key logs in only on a connection whose PROXY protocol v2 header carries the gateway's statement for this
// computer and that key, signed by a trusted CA key, made within VouchMaxAge (compute/v1 README §3, AgentCompute#353).

// dialVouched writes header (none when nil) first, as the gateway does, then logs in with key.
func (h *harness) dialVouched(t *testing.T, header []byte, key gossh.Signer, hostKey gossh.HostKeyCallback) (*gossh.Client, error) {
	t.Helper()
	raw, err := net.DialTimeout("tcp", h.addr, 15*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if header != nil {
		if _, err := raw.Write(header); err != nil {
			t.Fatal(err)
		}
	}
	if hostKey == nil {
		hostKey = gossh.FixedHostKey(h.hostKey)
	}
	c, chans, reqs, err := gossh.NewClientConn(raw, h.addr, &gossh.ClientConfig{User: "anyone", Auth: []gossh.AuthMethod{gossh.PublicKeys(key)}, HostKeyCallback: hostKey, Timeout: 15 * time.Second})
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	client := gossh.NewClient(c, chans, reqs)
	t.Cleanup(func() { _ = client.Close() })
	return client, nil
}

func TestVouchedKeyLogsIn(t *testing.T) {
	h := start(t)
	key := newSigner(t)
	header, err := Vouch(h.ca, testComputer, key.PublicKey(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	c, err := h.dialVouched(t, header, key, nil)
	if err != nil {
		t.Fatalf("a vouched key: %v", err)
	}
	if out, _, code := run(t, c, "echo vouched", nil); code != 0 || strings.TrimSpace(out) != "vouched" {
		t.Fatalf("exec: %q %d", out, code)
	}
}

func TestPlainKeysRefused(t *testing.T) {
	h := start(t)
	key, other := newSigner(t), newSigner(t)
	stranger := newSigner(t)
	cases := map[string]func() []byte{
		"no header": func() []byte { return nil },
		"another key": func() []byte {
			b, _ := Vouch(h.ca, testComputer, other.PublicKey(), time.Now())
			return b
		},
		"another computer": func() []byte {
			b, _ := Vouch(h.ca, "cmp_other1", key.PublicKey(), time.Now())
			return b
		},
		"too old": func() []byte {
			b, _ := Vouch(h.ca, testComputer, key.PublicKey(), time.Now().Add(-VouchMaxAge-time.Second))
			return b
		},
		"from the future": func() []byte {
			b, _ := Vouch(h.ca, testComputer, key.PublicKey(), time.Now().Add(time.Minute))
			return b
		},
		"signed by another key": func() []byte {
			b, _ := Vouch(stranger, testComputer, key.PublicKey(), time.Now())
			return b
		},
	}
	for name, header := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := h.dialVouched(t, header(), key, nil); err == nil {
				t.Fatal("logged in")
			}
		})
	}
}

// The edge's certificate login still works on a connection without a header (the gateway's own logins).
func TestCertificateWithoutHeader(t *testing.T) {
	h := start(t)
	if _, err := h.dialCert(t, nil); err != nil {
		t.Fatal(err)
	}
}

func TestHostCertificate(t *testing.T) {
	var hostKey gossh.Signer
	var ca gossh.Signer = newSigner(t)
	h := startWith(t, func(c *Config) {
		hostKey = c.HostKey
		cert := &gossh.Certificate{Key: c.HostKey.PublicKey(), CertType: gossh.HostCert, KeyId: testComputer, ValidPrincipals: []string{testComputer}, ValidBefore: gossh.CertTimeInfinity}
		if err := cert.SignCert(rand.Reader, ca); err != nil {
			t.Fatal(err)
		}
		c.HostCertificate = string(gossh.MarshalAuthorizedKey(cert))
	})
	checker := &gossh.CertChecker{IsHostAuthority: func(auth gossh.PublicKey, address string) bool {
		return string(auth.Marshal()) == string(ca.PublicKey().Marshal())
	}}
	key := newSigner(t)
	header, _ := Vouch(h.ca, testComputer, key.PublicKey(), time.Now())
	// The client names the computer by its id, as `ssh <id>` does through the gateway.
	if _, err := h.dialVouched(t, header, key, func(_ string, remote net.Addr, k gossh.PublicKey) error {
		return checker.CheckHostKey(testComputer+":22", remote, k)
	}); err != nil {
		t.Fatalf("the host certificate: %v", err)
	}
	// A client that pins the plain host key still finds it.
	header, _ = Vouch(h.ca, testComputer, key.PublicKey(), time.Now())
	raw, _ := net.Dial("tcp", h.addr)
	_, _ = raw.Write(header)
	c, _, _, err := gossh.NewClientConn(raw, h.addr, &gossh.ClientConfig{User: "x", Auth: []gossh.AuthMethod{gossh.PublicKeys(key)}, HostKeyCallback: gossh.FixedHostKey(hostKey.PublicKey()), HostKeyAlgorithms: []string{gossh.KeyAlgoED25519}, Timeout: 15 * time.Second})
	if err != nil {
		t.Fatalf("the plain host key: %v", err)
	}
	_ = c.Close()
	// A certificate for another key is refused at start.
	other := newSigner(t)
	cert := &gossh.Certificate{Key: other.PublicKey(), CertType: gossh.HostCert, ValidPrincipals: []string{testComputer}, ValidBefore: gossh.CertTimeInfinity}
	_ = cert.SignCert(rand.Reader, ca)
	if _, err := HostCertSigner(hostKey, string(gossh.MarshalAuthorizedKey(cert))); err == nil || !strings.Contains(err.Error(), "not this computer's host key") {
		t.Fatalf("a certificate for another key: %v", errors.Unwrap(err))
	}
}

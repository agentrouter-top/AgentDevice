package sshd

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"
)

// A certificate as AgentCompute issues it logs in, and the session knows who it acts for.
func TestCertificateLogin(t *testing.T) {
	h := start(t)
	c := h.client(t)
	out, _, code := run(t, c, pick("echo ok", "Write-Output ok"), nil)
	if code != 0 || out == "" {
		t.Fatalf("out %q code %d", out, code)
	}
	deadline := time.After(10 * time.Second)
	for {
		select {
		case a := <-h.acts:
			if a.Kind == "exec" {
				if a.Sub != "svc_agenthost" || a.Run != "cnv_test1" {
					t.Fatalf("activity names %q / %q, want the certificate's sub and run", a.Sub, a.Run)
				}
				return
			}
		case <-deadline:
			t.Fatal("no activity for the command")
		}
	}
}

// Over the wire: a certificate for another computer, an expired one, one of another CA and a plain key are refused.
func TestCertificateLoginRefusals(t *testing.T) {
	h := start(t)
	other := newSigner(t)
	cases := map[string]func() (*gossh.Client, error){
		"another computer": func() (*gossh.Client, error) {
			return h.dialCert(t, func(c *gossh.Certificate) { c.ValidPrincipals = []string{"cmp_other"} })
		},
		"expired": func() (*gossh.Client, error) {
			return h.dialCert(t, func(c *gossh.Certificate) {
				c.ValidAfter, c.ValidBefore = uint64(time.Now().Add(-20*time.Minute).Unix()), uint64(time.Now().Add(-10*time.Minute).Unix())
			})
		},
		"another CA": func() (*gossh.Client, error) {
			_, s := certificate(t, other, nil)
			return h.dialWith(t, gossh.PublicKeys(s))
		},
		"plain key": func() (*gossh.Client, error) { return h.dialWith(t, gossh.PublicKeys(newSigner(t))) },
	}
	for name, dial := range cases {
		t.Run(name, func(t *testing.T) {
			if c, err := dial(); err == nil {
				c.Close()
				t.Fatal("accepted")
			}
		})
	}
}

// Every check names itself.
func TestCertificateChecks(t *testing.T) {
	ca, other := newSigner(t), newSigner(t)
	keys := &CAKeys{}
	if err := keys.Set([]string{authorizedKey(ca.PublicKey())}); err != nil {
		t.Fatal(err)
	}
	auth := &CertAuthority{Keys: keys, ComputerID: testComputer, Own: testOwner, Ten: testTenant}
	now := time.Now()
	cases := []struct {
		name  string
		by    gossh.Signer
		edit  func(*gossh.Certificate)
		check string
	}{
		{"accepted", ca, nil, ""},
		{"wrong signer", other, nil, "signer"},
		{"another computer", ca, func(c *gossh.Certificate) { c.ValidPrincipals = []string{"cmp_other"} }, "principal"},
		{"two principals", ca, func(c *gossh.Certificate) { c.ValidPrincipals = []string{testComputer, "cmp_other"} }, "principal"},
		{"no principal", ca, func(c *gossh.Certificate) { c.ValidPrincipals = nil }, "principal"},
		{"expired", ca, func(c *gossh.Certificate) { c.ValidBefore = uint64(now.Add(-time.Second).Unix()) }, "validity"},
		{"not yet valid", ca, func(c *gossh.Certificate) { c.ValidAfter = uint64(now.Add(time.Minute).Unix()) }, "validity"},
		{"never expires", ca, func(c *gossh.Certificate) { c.ValidBefore = gossh.CertTimeInfinity }, "validity"},
		{"critical option", ca, func(c *gossh.Certificate) { c.CriticalOptions = map[string]string{"force-command": "true"} }, "critical-option"},
		{"source-address", ca, func(c *gossh.Certificate) { c.CriticalOptions = map[string]string{"source-address": "0.0.0.0/0"} }, "critical-option"},
		{"another owner", ca, func(c *gossh.Certificate) { c.Permissions.Extensions[ExtOwn] = "acc_9999" }, "own"},
		{"no owner", ca, func(c *gossh.Certificate) { delete(c.Permissions.Extensions, ExtOwn) }, "own"},
		{"another tenant", ca, func(c *gossh.Certificate) { c.Permissions.Extensions[ExtTen] = "acc_9998" }, "ten"},
		{"host certificate", ca, func(c *gossh.Certificate) { c.CertType = gossh.HostCert }, "type"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cert, _ := certificate(t, tc.by, tc.edit)
			caller, err := auth.Verify(context.Background(), cert)
			if tc.check == "" {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				if caller.Method != "certificate" || caller.Own != testOwner || caller.Sub != "svc_agenthost" || caller.Run != "cnv_test1" || caller.Serial != 4242 || caller.KeyID == "" {
					t.Fatalf("caller %+v", caller)
				}
				return
			}
			var ce *CertError
			if !errors.As(err, &ce) || ce.Check != tc.check {
				t.Fatalf("got %v, want the %s check", err, tc.check)
			}
		})
	}

	// A signature that does not verify (the certificate changed after signing) is refused.
	cert, _ := certificate(t, ca, nil)
	cert.Permissions.Extensions[ExtSub] = "acc_someone_else"
	var ce *CertError
	if _, err := auth.Verify(context.Background(), cert); !errors.As(err, &ce) || ce.Check != "signature" {
		t.Fatalf("tampered certificate: %v", err)
	}

	// The tenant is checked only when this computer knows it.
	noTen := &CertAuthority{Keys: keys, ComputerID: testComputer, Own: testOwner}
	cert, _ = certificate(t, ca, func(c *gossh.Certificate) { c.Permissions.Extensions[ExtTen] = "acc_9998" })
	if _, err := noTen.Verify(context.Background(), cert); err != nil {
		t.Fatalf("tenant unknown here, but refused: %v", err)
	}
}

// A rotation: a certificate of a CA this computer does not know yet makes it ask for the keys again (once per
// interval), and the old and the new key are trusted together.
func TestCARotationRefreshesOnce(t *testing.T) {
	oldCA, newCA := newSigner(t), newSigner(t)
	var asked atomic.Int32
	keys := &CAKeys{MinInterval: time.Hour, Refresh: func(context.Context) ([]string, error) {
		asked.Add(1)
		return []string{authorizedKey(newCA.PublicKey()), authorizedKey(oldCA.PublicKey())}, nil
	}}
	if err := keys.Set([]string{authorizedKey(oldCA.PublicKey())}); err != nil {
		t.Fatal(err)
	}
	auth := &CertAuthority{Keys: keys, ComputerID: testComputer, Own: testOwner, Ten: testTenant}
	byNew, _ := certificate(t, newCA, nil)
	if _, err := auth.Verify(context.Background(), byNew); err != nil {
		t.Fatalf("new CA after a refresh: %v", err)
	}
	byOld, _ := certificate(t, oldCA, nil)
	if _, err := auth.Verify(context.Background(), byOld); err != nil {
		t.Fatalf("old CA during the rotation: %v", err)
	}
	stranger, _ := certificate(t, newSigner(t), nil)
	for range 3 {
		if _, err := auth.Verify(context.Background(), stranger); err == nil {
			t.Fatal("an unknown CA was accepted")
		}
	}
	if n := asked.Load(); n != 1 {
		t.Fatalf("asked for the keys %d times, want once within the interval", n)
	}
}

func TestCAKeysTakeOnlyPlainPublicKeys(t *testing.T) {
	ca := newSigner(t)
	cert, _ := certificate(t, ca, nil)
	k := &CAKeys{}
	if err := k.Set([]string{authorizedKey(ca.PublicKey())}); err != nil {
		t.Fatal(err)
	}
	for name, lines := range map[string][]string{
		"empty":       nil,
		"garbage":     {"not a key"},
		"certificate": {authorizedKey(cert)},
	} {
		if err := k.Set(lines); err == nil {
			t.Fatalf("%s: taken", name)
		}
	}
	if fps := k.Fingerprints(); len(fps) != 1 || fps[0] != gossh.FingerprintSHA256(ca.PublicKey()) {
		t.Fatalf("a refused Set changed the trusted keys: %v", fps)
	}
}

// The session's caller is the certificate that logged in, not the last one the client offered.
func TestCallerIsTheCertificateThatLoggedIn(t *testing.T) {
	h := start(t)
	// The first certificate offered names another computer (refused); the second logs in.
	_, wrong := certificate(t, h.ca, func(c *gossh.Certificate) {
		c.ValidPrincipals = []string{"cmp_other"}
		c.Permissions.Extensions[ExtRun] = "cnv_wrong"
	})
	_, right := certificate(t, h.ca, nil)
	c, err := h.dialWith(t, gossh.PublicKeys(wrong, right))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	run(t, c, pick("echo ok", "Write-Output ok"), nil)
	deadline := time.After(10 * time.Second)
	for {
		select {
		case a := <-h.acts:
			if a.Kind == "exec" {
				if a.Run != "cnv_test1" {
					t.Fatalf("activity run %q, want the logged-in certificate's", a.Run)
				}
				return
			}
		case <-deadline:
			t.Fatal("no activity")
		}
	}
}

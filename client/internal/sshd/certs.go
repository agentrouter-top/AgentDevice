package sshd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"charm.land/ssh"
	gossh "golang.org/x/crypto/ssh"
)

// Certificate logins (compute/v1 README §3; AgentCompute#179, owner 2026-11-11 「ssh用证书方案，按你推荐的来」): the SSH
// credential is a short-lived OpenSSH user certificate AgentCompute's SSH user CA signs for one computer
// (POST /v1/computers/{id}/access { publicKey }). AgentCompute's SSH gateway checks it before it forwards; this server is
// the last hop and checks it again against the CA keys it was given. golang.org/x/crypto/ssh parses and verifies the
// certificate (the library the gateway uses, ssh-gateway/internal/ca); the checks around it mirror the gateway's.

// Extensions AgentCompute's CA writes (ssh-gateway/internal/ca): who the certificate acts for and the authorising token.
const (
	ExtOwn = "own@agentcompute.agentrouter.top"
	ExtTen = "ten@agentcompute.agentrouter.top"
	ExtSub = "sub@agentcompute.agentrouter.top"
	ExtRun = "run@agentcompute.agentrouter.top"
	ExtDlg = "dlg@agentcompute.agentrouter.top"
	ExtJti = "jti@agentcompute.agentrouter.top"
)

// CertError is a refused certificate: Check names the failed check (type, critical-option, principal, signer,
// validity, signature, own, ten), Detail says why. It never carries key material.
type CertError struct {
	Check  string
	Detail string
}

func (e *CertError) Error() string { return "ssh certificate refused (" + e.Check + "): " + e.Detail }

// Caller is who authenticated a connection, for the session log and the activity log.
type Caller struct {
	Method string // certificate | token (the former password path, legacy_token.go)
	Own    string
	Sub    string
	Run    string
	Dlg    string
	Jti    string
	Serial uint64 // certificate only
	KeyID  string // certificate only: "<computer> own=… sub=… jti=…[ run=…][ dlg=…]"
}

// CAKeys is the set of SSH user CA public keys this computer trusts: more than one during a rotation (compute/v1
// sshUserCAKeys). Safe for concurrent use.
type CAKeys struct {
	// Refresh, when set, fetches the current keys (a device: compute/v1 GET /v1/ssh-user-ca; a sandbox: its join file
	// again). It is asked when a certificate names a signer this computer does not know, so a CA rotation does not need
	// a restart; at most once per MinInterval, so unknown signers cannot make the client call out on every attempt.
	Refresh     func(context.Context) ([]string, error)
	MinInterval time.Duration
	Log         *slog.Logger

	mu    sync.Mutex
	keys  []gossh.PublicKey
	asked time.Time
}

// ParseCAKeys parses authorized_keys lines (compute/v1 sshUserCAKeys). A line that is not one plain public key (a
// certificate included) is an error naming its position, never its content.
func ParseCAKeys(lines []string) ([]gossh.PublicKey, error) {
	out := make([]gossh.PublicKey, 0, len(lines))
	for i, line := range lines {
		k, _, _, rest, err := gossh.ParseAuthorizedKey([]byte(line))
		if err != nil || len(bytes.TrimSpace(rest)) > 0 {
			return nil, fmt.Errorf("ssh user CA key %d of %d is not one OpenSSH public key (authorized_keys format)", i+1, len(lines))
		}
		if _, isCert := k.(*gossh.Certificate); isCert {
			return nil, fmt.Errorf("ssh user CA key %d of %d is a certificate, not a CA public key", i+1, len(lines))
		}
		out = append(out, k)
	}
	return out, nil
}

// Set replaces the trusted keys. An empty list or one with an unusable line keeps the current keys (an answer
// without keys is a misconfigured CA, not a withdrawal of trust).
func (k *CAKeys) Set(lines []string) error {
	if len(lines) == 0 {
		return errors.New("ssh user CA: no keys given; the trusted keys stay as they were")
	}
	keys, err := ParseCAKeys(lines)
	if err != nil {
		return fmt.Errorf("%w; the trusted keys stay as they were", err)
	}
	k.mu.Lock()
	k.keys = keys
	k.mu.Unlock()
	return nil
}

// Fingerprints are the trusted keys' SHA256 fingerprints, sorted (for logs).
func (k *CAKeys) Fingerprints() []string {
	k.mu.Lock()
	defer k.mu.Unlock()
	out := make([]string, 0, len(k.keys))
	for _, key := range k.keys {
		out = append(out, gossh.FingerprintSHA256(key))
	}
	sort.Strings(out)
	return out
}

func (k *CAKeys) trusts(key gossh.PublicKey) bool {
	if key == nil {
		return false
	}
	want := key.Marshal()
	k.mu.Lock()
	defer k.mu.Unlock()
	for _, t := range k.keys {
		if bytes.Equal(t.Marshal(), want) {
			return true
		}
	}
	return false
}

// refreshForUnknown asks Refresh once (unless it was asked within MinInterval) and reports whether the keys changed.
func (k *CAKeys) refreshForUnknown(ctx context.Context) bool {
	k.mu.Lock()
	if k.Refresh == nil || (!k.asked.IsZero() && time.Since(k.asked) < k.MinInterval) {
		k.mu.Unlock()
		return false
	}
	k.asked = time.Now()
	k.mu.Unlock()
	before := strings.Join(k.Fingerprints(), ",")
	rctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	lines, err := k.Refresh(rctx)
	if err == nil {
		err = k.Set(lines)
	}
	log := k.Log
	if log == nil {
		log = slog.Default()
	}
	if err != nil {
		log.Warn("ssh user CA: refreshing the trusted keys failed; keeping the current ones", "error", err.Error())
		return false
	}
	after := strings.Join(k.Fingerprints(), ",")
	log.Info("ssh user CA: trusted keys refreshed", "keys", after, "changed", after != before)
	return after != before
}

// CertAuthority checks certificate logins for one computer.
type CertAuthority struct {
	Keys       *CAKeys
	ComputerID string
	// Own is the computer's owner (identity/v1 account id); Ten its tenant, checked when known.
	Own string
	Ten string
	Now func() time.Time
}

// Verify checks a certificate presented at login: an OpenSSH user certificate, no critical option, exactly one
// principal equal to this computer's id, signed by a trusted CA key (asking for the keys again once when the signer is
// unknown), valid now, a valid signature, and AgentCompute's own@ (and ten@, when the tenant is known) equal to this
// computer's. It returns the caller, or a *CertError.
func (a *CertAuthority) Verify(ctx context.Context, cert *gossh.Certificate) (*Caller, error) {
	if cert.CertType != gossh.UserCert {
		return nil, &CertError{"type", "a host certificate, not a user certificate"}
	}
	// Every critical option is refused, source-address included (x/crypto's CheckCert leaves that one to
	// CertChecker.Authenticate, which this server does not use).
	if len(cert.CriticalOptions) > 0 {
		names := make([]string, 0, len(cert.CriticalOptions))
		for n := range cert.CriticalOptions {
			names = append(names, n)
		}
		sort.Strings(names)
		return nil, &CertError{"critical-option", fmt.Sprintf("critical options %v are not taken here", names)}
	}
	if len(cert.ValidPrincipals) != 1 || cert.ValidPrincipals[0] != a.ComputerID {
		return nil, &CertError{"principal", fmt.Sprintf("the certificate names principals %q; this computer is %s (POST /v1/computers/%s/access issues one for it)", cert.ValidPrincipals, a.ComputerID, a.ComputerID)}
	}
	// CheckCert checks the signature, validity and principal but not who signed (ssh.CertChecker.Authenticate does,
	// but takes the login user as the principal; ours is the computer): the signer is checked here first.
	if !a.Keys.trusts(cert.SignatureKey) && !(a.Keys.refreshForUnknown(ctx) && a.Keys.trusts(cert.SignatureKey)) {
		signer := "none"
		if cert.SignatureKey != nil {
			signer = gossh.FingerprintSHA256(cert.SignatureKey)
		}
		return nil, &CertError{"signer", fmt.Sprintf("signed by %s, not one of this computer's trusted SSH user CA keys %v", signer, a.Keys.Fingerprints())}
	}
	now := time.Now()
	if a.Now != nil {
		now = a.Now()
	}
	after, before := time.Unix(int64(cert.ValidAfter), 0).UTC(), time.Unix(int64(cert.ValidBefore), 0).UTC()
	switch {
	case cert.ValidBefore == gossh.CertTimeInfinity:
		return nil, &CertError{"validity", "the certificate never expires; AgentCompute's are valid for minutes"}
	case int64(cert.ValidAfter) < 0 || now.Unix() < int64(cert.ValidAfter):
		return nil, &CertError{"validity", fmt.Sprintf("valid from %s, now is %s (this computer's clock may be behind)", after.Format(time.RFC3339), now.UTC().Format(time.RFC3339))}
	case int64(cert.ValidBefore) < 0 || now.Unix() >= int64(cert.ValidBefore):
		return nil, &CertError{"validity", fmt.Sprintf("expired at %s, now is %s: ask POST /v1/computers/%s/access for a new one", before.Format(time.RFC3339), now.UTC().Format(time.RFC3339), a.ComputerID)}
	}
	checker := &gossh.CertChecker{Clock: func() time.Time { return now }}
	if err := checker.CheckCert(a.ComputerID, cert); err != nil {
		return nil, &CertError{"signature", err.Error()}
	}
	ext := cert.Permissions.Extensions
	if ext[ExtOwn] != a.Own {
		return nil, &CertError{"own", fmt.Sprintf("the certificate acts for owner %q; this computer belongs to %s", ext[ExtOwn], a.Own)}
	}
	if a.Ten != "" && ext[ExtTen] != a.Ten {
		return nil, &CertError{"ten", fmt.Sprintf("the certificate is for tenant %q; this computer's is %s", ext[ExtTen], a.Ten)}
	}
	return &Caller{Method: "certificate", Own: ext[ExtOwn], Sub: ext[ExtSub], Run: ext[ExtRun], Dlg: ext[ExtDlg], Jti: ext[ExtJti],
		Serial: cert.Serial, KeyID: cert.KeyId}, nil
}

type callerKey struct{}

// publicKey authenticates with an AgentCompute SSH user certificate. The library asks for the proof that the client
// holds the private key only after this accepted the key, so accepting here is not yet a login. The caller goes into
// this key's own permissions (charm.land/ssh starts fresh ones per attempt and keeps those of the key that logged in),
// so the session sees the certificate that authenticated, not the last one offered.
func (s *Server) publicKey(ctx ssh.Context, key ssh.PublicKey) bool {
	cert, ok := key.(*gossh.Certificate)
	if !ok {
		s.cfg.Log.Info("ssh auth denied", "remote", ctx.RemoteAddr().String(), "user", ctx.User(), "method", "publickey", "check", "certificate",
			"error", "a plain key; only certificates from POST /v1/computers/{id}/access log in with a key", "key", gossh.FingerprintSHA256(key))
		return false
	}
	c, err := s.cfg.Certificates.Verify(ctx, cert)
	if err != nil {
		check := ""
		var ce *CertError
		if errors.As(err, &ce) {
			check = ce.Check
		}
		s.cfg.Log.Warn("ssh auth denied", "remote", ctx.RemoteAddr().String(), "user", ctx.User(), "method", "certificate", "check", check,
			"serial", cert.Serial, "keyId", cert.KeyId, "error", err.Error())
		return false
	}
	setCaller(ctx, c)
	s.cfg.Log.Info("ssh certificate accepted", "remote", ctx.RemoteAddr().String(), "user", ctx.User(), "method", "certificate",
		"serial", c.Serial, "keyId", c.KeyID, "own", c.Own, "sub", c.Sub, "run", c.Run, "dlg", c.Dlg, "jti", c.Jti)
	return true
}

func setCaller(ctx ssh.Context, c *Caller) {
	p := ctx.Permissions()
	if p.ExtraData == nil {
		p.ExtraData = map[any]any{}
	}
	p.ExtraData[callerKey{}] = c
}

// callerOf is the caller of an authenticated connection (nil before authentication).
func callerOf(ctx ssh.Context) *Caller {
	if p := ctx.Permissions(); p != nil && p.Permissions != nil {
		if c, ok := p.ExtraData[callerKey{}].(*Caller); ok {
			return c
		}
	}
	return nil
}

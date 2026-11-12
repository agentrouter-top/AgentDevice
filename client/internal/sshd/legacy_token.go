package sshd

// LEGACY: the token password (aud netbird) — delete this file once AgentHost logs in with certificates
// (AgentHost#385; deletion tracked on AgentDevice#253). Removing it is a pure delete: this file, Config.Authorizer
// and the one PasswordHandler line in New, the Authorizer in app.go (with its identity.Verifier), and the tests in
// legacy_token_test.go. compute/v1 README §3 accepts this credential only until AgentHost and AgentDevice moved.

import (
	"context"
	"fmt"
	"time"

	"charm.land/ssh"

	"github.com/agentrouter-top/AgentDevice/client/internal/identity"
)

// Authorizer decides whether an SSH password (an identity/v1 token) may open a session on this device:
// aud netbird, scp covering computer:<this id>:ssh, own equal to the device's owner, ten equal to the tenant of the
// device's login (when known; identity/v1: layers check owner and tenant), and issued at most MaxAge ago
// (compute/v1 access tokenMaxAgeSeconds). AgentCompute's SSH gateway checks the same token before forwarding; the
// device checks it again because it is the last hop.
type Authorizer struct {
	Verifier   *identity.Verifier
	ComputerID string
	Own        string
	Ten        string
	MaxAge     time.Duration
}

// Audience is the identity/v1 audience of SSH tokens.
const Audience = "netbird"

// Authorize returns the token's claims, or an *identity.Error naming the failed check.
func (a *Authorizer) Authorize(ctx context.Context, token string) (*identity.Claims, error) {
	scope := "computer:" + a.ComputerID + ":ssh"
	c, err := a.Verifier.Verify(ctx, token, Audience, scope)
	if err != nil {
		return nil, err
	}
	if c.Own != a.Own {
		return nil, &identity.Error{Check: "own", Detail: fmt.Sprintf("own %s, this device belongs to %s", c.Own, a.Own)}
	}
	if a.Ten != "" && c.Ten != a.Ten {
		return nil, &identity.Error{Check: "ten", Detail: fmt.Sprintf("ten %s, this device's login is for tenant %s", c.Ten, a.Ten)}
	}
	now := time.Now()
	if a.Verifier.Now != nil {
		now = a.Verifier.Now()
	}
	if age := now.Sub(time.Unix(c.Iat, 0)); a.MaxAge > 0 && age > a.MaxAge {
		return nil, &identity.Error{Check: "age", Detail: fmt.Sprintf("issued %s ago, at most %s when connecting: mint the token right before connecting", age.Truncate(time.Second), a.MaxAge)}
	}
	return c, nil
}

// legacyPassword authenticates with the token; the token itself is never logged.
func (s *Server) legacyPassword(ctx ssh.Context, password string) bool {
	c, err := s.cfg.Authorizer.Authorize(ctx, password)
	if err != nil {
		s.cfg.Log.Warn("ssh auth denied", "remote", ctx.RemoteAddr().String(), "user", ctx.User(), "method", "token (legacy)", "check", identity.Check(err), "error", err.Error())
		return false
	}
	setCaller(ctx, &Caller{Method: "token", Own: c.Own, Sub: c.Sub, Run: c.Run, Jti: c.Jti})
	s.cfg.Log.Info("ssh auth granted", "remote", ctx.RemoteAddr().String(), "user", ctx.User(), "method", "token (legacy)", "sub", c.Sub, "run", c.Run, "jti", c.Jti)
	return true
}

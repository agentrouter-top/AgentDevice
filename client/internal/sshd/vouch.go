package sshd

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net"
	"time"

	"charm.land/ssh"
	proxyproto "github.com/pires/go-proxyproto"
	gossh "golang.org/x/crypto/ssh"
)

// Registered keys (compute/v1 README §3, AgentCompute#353): a buyer logs in with its own key, registered on this
// computer at the store. The SSH gateway checks that registration at every connection it forwards and vouches for the
// key to this server: before the caller's SSH bytes it writes a PROXY protocol v2 header (the standard a proxy uses to
// tell a backend about a connection; github.com/pires/go-proxyproto, Apache-2.0) with two TLVs of the custom range,
// a statement and its signature by one of the CA keys this computer trusts. This server then takes that one plain
// key on that one connection and nothing else; a connection without such a header (another computer of the owner's
// network) has no plain-key login. Nothing about the keys is kept here: the gateway asks compute/v1 each time.

const (
	// VouchStatementTLV holds the statement, JSON {"v":1,"computer","key","at"} (compute/v1 README §3).
	VouchStatementTLV = proxyproto.PP2Type(0xE0)
	// VouchSignatureTLV holds the SSH signature (RFC 4253 §6.6 wire format) over VouchDomain + the statement.
	VouchSignatureTLV = proxyproto.PP2Type(0xE1)
	// VouchDomain separates these signatures from anything else the CA key signs (certificates).
	VouchDomain = "agentcompute-vouch-v1\x00"
	// VouchMaxAge: a statement older than this is refused (it is made for one connection, a moment before it opens;
	// a statement copied by whoever was root here cannot be used later, after its key was removed).
	VouchMaxAge = 2 * time.Minute
	// vouchSkew: how far ahead of this computer's clock a statement may be.
	vouchSkew = 30 * time.Second
)

// Statement is what the gateway vouches for: key (an authorized_keys line without a comment) is registered on
// computer at the moment at (Unix seconds).
type Statement struct {
	V        int    `json:"v"`
	Computer string `json:"computer"`
	Key      string `json:"key"`
	At       int64  `json:"at"`
}

// voucher is a connection's PROXY header TLVs, unchecked (checked at the key's login, against the key offered).
type voucher struct {
	statement []byte
	signature []byte
}

type voucherKey struct{}

// readVoucher is the server's ConnCallback: it reads the PROXY protocol v2 header, when the connection starts with
// one, and keeps its statement for the login. A connection without a header is read unchanged (the endpoint edge's
// certificate login). A malformed header ends the connection.
func (s *Server) readVoucher(ctx ssh.Context, conn net.Conn) net.Conn {
	pc := proxyproto.NewConn(conn, proxyproto.SetReadHeaderTimeout(30*time.Second))
	h := pc.ProxyHeader()
	if h == nil {
		return pc
	}
	tlvs, err := h.TLVs()
	if err != nil {
		s.cfg.Log.Warn("ssh connection refused: its PROXY header's TLVs do not parse", "remote", conn.RemoteAddr().String(), "error", err.Error())
		return nil
	}
	var v voucher
	for _, t := range tlvs {
		switch t.Type {
		case VouchStatementTLV:
			v.statement = t.Value
		case VouchSignatureTLV:
			v.signature = t.Value
		}
	}
	if v.statement != nil {
		ctx.SetValue(voucherKey{}, &v)
	}
	return pc
}

// VouchError is a plain key refused: Check names the failed check (voucher, signature, statement, computer, key,
// age), Detail says why. It never carries key material beyond fingerprints.
type VouchError struct {
	Check  string
	Detail string
}

func (e *VouchError) Error() string { return "ssh key refused (" + e.Check + "): " + e.Detail }

// verifyVouched checks that the connection's statement is signed by a trusted CA key (asking for the keys again once
// when none verifies), names this computer and exactly key, and was made within VouchMaxAge.
func (a *CertAuthority) verifyVouched(ctx context.Context, v *voucher, key gossh.PublicKey) (*Statement, error) {
	if v == nil {
		return nil, &VouchError{"voucher", "a plain key, on a connection the SSH gateway did not vouch for: keys log in through the gateway only (ssh <computer id> after the store's SSH setup)"}
	}
	sig := new(gossh.Signature)
	if err := gossh.Unmarshal(v.signature, sig); err != nil {
		return nil, &VouchError{"signature", "the gateway's statement carries no readable signature"}
	}
	signed := append([]byte(VouchDomain), v.statement...)
	if !a.Keys.verifies(signed, sig) && !(a.Keys.refreshForUnknown(ctx) && a.Keys.verifies(signed, sig)) {
		return nil, &VouchError{"signature", fmt.Sprintf("the statement is not signed by one of this computer's trusted CA keys %v", a.Keys.Fingerprints())}
	}
	var st Statement
	dec := json.NewDecoder(bytes.NewReader(v.statement))
	if err := dec.Decode(&st); err != nil || st.V != 1 {
		return nil, &VouchError{"statement", "the gateway's statement is not version 1 JSON"}
	}
	if st.Computer != a.ComputerID {
		return nil, &VouchError{"computer", fmt.Sprintf("the gateway vouched for a key on %s; this computer is %s", st.Computer, a.ComputerID)}
	}
	vouched, _, _, _, err := gossh.ParseAuthorizedKey([]byte(st.Key))
	if err != nil {
		return nil, &VouchError{"statement", "the statement's key is not an OpenSSH public key"}
	}
	if !bytes.Equal(vouched.Marshal(), key.Marshal()) {
		return nil, &VouchError{"key", fmt.Sprintf("the gateway vouched for %s; this login offered %s", gossh.FingerprintSHA256(vouched), gossh.FingerprintSHA256(key))}
	}
	now := time.Now()
	if a.Now != nil {
		now = a.Now()
	}
	at := time.Unix(st.At, 0)
	if at.After(now.Add(vouchSkew)) || now.Sub(at) > VouchMaxAge {
		return nil, &VouchError{"age", fmt.Sprintf("the statement was made at %s, this computer's clock says %s (more than %s apart): connect again; if it keeps failing, this computer's clock is wrong", at.UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339), VouchMaxAge)}
	}
	return &st, nil
}

// verifies: one of the trusted keys made sig over data.
func (k *CAKeys) verifies(data []byte, sig *gossh.Signature) bool {
	k.mu.Lock()
	keys := append([]gossh.PublicKey(nil), k.keys...)
	k.mu.Unlock()
	for _, t := range keys {
		if t.Verify(data, sig) == nil {
			return true
		}
	}
	return false
}

// Vouch makes the PROXY protocol v2 header the gateway writes for key on computer (tests; AgentCompute's gateway has
// its own copy of these few lines, compute/v1 README §3 is the definition both follow).
func Vouch(signer gossh.Signer, computer string, key gossh.PublicKey, at time.Time) ([]byte, error) {
	line := string(bytes.TrimSpace(gossh.MarshalAuthorizedKey(key)))
	st, err := json.Marshal(Statement{V: 1, Computer: computer, Key: line, At: at.Unix()})
	if err != nil {
		return nil, err
	}
	sig, err := signer.Sign(rand.Reader, append([]byte(VouchDomain), st...))
	if err != nil {
		return nil, err
	}
	h := &proxyproto.Header{Version: 2, Command: proxyproto.LOCAL, TransportProtocol: proxyproto.UNSPEC}
	if err := h.SetTLVs([]proxyproto.TLV{{Type: VouchStatementTLV, Value: st}, {Type: VouchSignatureTLV, Value: gossh.Marshal(sig)}}); err != nil {
		return nil, err
	}
	return h.Format()
}

func voucherOf(ctx ssh.Context) *voucher {
	v, _ := ctx.Value(voucherKey{}).(*voucher)
	return v
}

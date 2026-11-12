package sshd

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pkg/sftp"
	gossh "golang.org/x/crypto/ssh"

	"github.com/agentrouter-top/AgentDevice/client/internal/facts"
	"github.com/agentrouter-top/AgentDevice/client/internal/state"
)

// The tests log in with certificates of a test SSH user CA made per test (as AgentCompute's CA writes them,
// ssh-gateway/internal/ca) and run the real server on a loopback listener (the NetBird listener is a net.Listener too).
// They run on GitHub-hosted Linux, macOS and Windows runners (R47).

const (
	testComputer = "cmp_test1"
	testOwner    = "acc_2002"
	testTenant   = "acc_1001"
)

type harness struct {
	acts    chan Activity
	addr    string
	hostKey gossh.PublicKey
	home    string
	ca      gossh.Signer
}

func newSigner(t *testing.T) gossh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := gossh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func authorizedKey(k gossh.PublicKey) string {
	return strings.TrimSpace(string(gossh.MarshalAuthorizedKey(k)))
}

func start(t *testing.T) *harness { return startWith(t, nil) }

// startWith runs the server; edit changes its configuration first.
func startWith(t *testing.T, edit func(*Config)) *harness {
	t.Helper()
	signer, _, err := state.Dir(t.TempDir()).HostKey()
	if err != nil {
		t.Fatal(err)
	}
	ca := newSigner(t)
	keys := &CAKeys{}
	if err := keys.Set([]string{authorizedKey(ca.PublicKey())}); err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	acts := make(chan Activity, 64)
	cfg := Config{
		Activity: func(a Activity) {
			select {
			case acts <- a:
			default:
			}
		},
		HostKey:      signer,
		Certificates: &CertAuthority{Keys: keys, ComputerID: testComputer, Own: testOwner, Ten: testTenant},
		Shell:        facts.UserShell(),
		Home:         home,
		Version:      "test",
		Log:          slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	if edit != nil {
		edit(&cfg)
	}
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return &harness{acts: acts, addr: ln.Addr().String(), hostKey: signer.PublicKey(), home: home, ca: ca}
}

// certificate is a user certificate for a new key, as POST /v1/computers/{id}/access issues it, signed by ca after
// edit changed it.
func certificate(t *testing.T, ca gossh.Signer, edit func(*gossh.Certificate)) (*gossh.Certificate, gossh.Signer) {
	t.Helper()
	key := newSigner(t)
	now := time.Now()
	cert := &gossh.Certificate{
		Key: key.PublicKey(), Serial: 4242, CertType: gossh.UserCert,
		KeyId:           testComputer + " own=" + testOwner + " sub=svc_agenthost jti=j1 run=cnv_test1",
		ValidPrincipals: []string{testComputer},
		ValidAfter:      uint64(now.Add(-30 * time.Second).Unix()), ValidBefore: uint64(now.Add(10 * time.Minute).Unix()),
		Permissions: gossh.Permissions{Extensions: map[string]string{
			"permit-pty": "", "permit-port-forwarding": "",
			ExtOwn: testOwner, ExtTen: testTenant, "pay@agentcompute.agentrouter.top": testOwner, ExtSub: "svc_agenthost",
			ExtJti: "j1", ExtRun: "cnv_test1", "iat@agentcompute.agentrouter.top": fmt.Sprint(now.Unix()),
		}},
	}
	if edit != nil {
		edit(cert)
	}
	if err := cert.SignCert(rand.Reader, ca); err != nil {
		t.Fatal(err)
	}
	signer, err := gossh.NewCertSigner(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	return cert, signer
}

func (h *harness) dialWith(t *testing.T, auth ...gossh.AuthMethod) (*gossh.Client, error) {
	t.Helper()
	return gossh.Dial("tcp", h.addr, &gossh.ClientConfig{
		User:            "anyone",
		Auth:            auth,
		HostKeyCallback: gossh.FixedHostKey(h.hostKey),
		Timeout:         15 * time.Second,
	})
}

// dialCert logs in with a certificate of the harness's CA, changed by edit.
func (h *harness) dialCert(t *testing.T, edit func(*gossh.Certificate)) (*gossh.Client, error) {
	t.Helper()
	_, signer := certificate(t, h.ca, edit)
	return h.dialWith(t, gossh.PublicKeys(signer))
}

func (h *harness) client(t *testing.T) *gossh.Client {
	t.Helper()
	c, err := h.dialCert(t, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// run executes cmd and returns stdout, stderr and the exit code.
func run(t *testing.T, c *gossh.Client, cmd string, stdin io.Reader) (string, string, int) {
	t.Helper()
	s, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var out, errOut bytes.Buffer
	s.Stdout, s.Stderr, s.Stdin = &out, &errOut, stdin
	err = s.Run(cmd)
	code := 0
	var ee *gossh.ExitError
	switch {
	case errors.As(err, &ee):
		code = ee.ExitStatus()
	case err != nil:
		t.Fatalf("run %q: %v (stderr %q)", cmd, err, errOut.String())
	}
	return out.String(), errOut.String(), code
}

var onWindows = runtime.GOOS == "windows"

func pick(unix, ps string) string {
	if onWindows {
		return ps
	}
	return unix
}

func TestExecOutputExitCodeAndStdin(t *testing.T) {
	h := start(t)
	c := h.client(t)
	out, _, code := run(t, c, pick("echo hello; echo 中文", "Write-Output hello; Write-Output 中文"), nil)
	if code != 0 || !strings.Contains(out, "hello") || !strings.Contains(out, "中文") {
		t.Fatalf("out %q code %d", out, code)
	}
	if _, _, code := run(t, c, "exit 3", nil); code != 3 {
		t.Fatalf("exit 3 gave %d", code)
	}
	// The visible activity log gets one entry per command, with who and the first line.
	deadline := time.After(5 * time.Second)
	for found := false; !found; {
		select {
		case a := <-h.acts:
			found = a.Kind == "exec" && a.Command == "exit 3" && a.Exit == 3 && a.Run == "cnv_test1"
		case <-deadline:
			t.Fatal("no activity entry for `exit 3`")
		}
	}
	_, errOut, code := run(t, c, pick("echo oops >&2; false", "Write-Error oops"), nil)
	if code == 0 || !strings.Contains(errOut, "oops") {
		t.Fatalf("stderr %q code %d", errOut, code)
	}
	out, _, _ = run(t, c, pick("cat", "[Console]::In.ReadToEnd()"), strings.NewReader("from stdin\n"))
	if !strings.Contains(out, "from stdin") {
		t.Fatalf("stdin not passed: %q", out)
	}
}

// R21 regression: a command of 200 KiB (over Linux's 128 KiB per-argument limit and Windows' 32 767 characters) runs,
// because its text never travels in a command line. 200 KiB is the most an SSH exec request can carry: the protocol
// packet limit is 256 KiB (x/crypto maxPacket, OpenSSH the same), so a larger command is refused before it arrives.
func TestLargeCommandRuns(t *testing.T) {
	c := start(t).client(t)
	pad := strings.Repeat("x", 200<<10)
	cmd := pick(": "+pad+"\necho big-ok", "# "+pad+"\nWrite-Output big-ok")
	out, errOut, code := run(t, c, cmd, nil)
	if code != 0 || !strings.Contains(out, "big-ok") {
		t.Fatalf("out %.200q err %.200q code %d", out, errOut, code)
	}
	left, _ := filepath.Glob(filepath.Join(runDir(), "cmd-*.txt"))
	if len(left) > 0 {
		t.Logf("command files left (other runs may be concurrent): %v", left)
	}
}

func TestSFTPStartsInHomeAndRoundTrips(t *testing.T) {
	h := start(t)
	sc, err := sftp.NewClient(h.client(t))
	if err != nil {
		t.Fatal(err)
	}
	defer sc.Close()
	wd, err := sc.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	want, _ := filepath.EvalSymlinks(h.home)
	gotPath := filepath.FromSlash(strings.TrimPrefix(wd, "/"))
	if !onWindows {
		gotPath = wd
	}
	if g, _ := filepath.EvalSymlinks(gotPath); !strings.EqualFold(g, want) {
		t.Fatalf("SFTP starts in %q, want the home %q", wd, h.home)
	}
	payload := bytes.Repeat([]byte{0, 1, 2, 250, 251, 255}, 200000)
	f, err := sc.Create("roundtrip.bin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(payload); err != nil {
		t.Fatal(err)
	}
	f.Close()
	g, err := sc.Open("roundtrip.bin")
	if err != nil {
		t.Fatal(err)
	}
	back, _ := io.ReadAll(g)
	g.Close()
	if !bytes.Equal(back, payload) {
		t.Fatalf("read %d bytes back, want %d identical", len(back), len(payload))
	}
	if _, err := os.Stat(filepath.Join(h.home, "roundtrip.bin")); err != nil {
		t.Fatalf("file not in the home: %v", err)
	}
}

func TestForwardingOnlyToThisComputer(t *testing.T) {
	c := start(t).client(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = io.Copy(conn, conn)
	}()
	conn, err := c.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("forward to a loopback service refused: %v", err)
	}
	fmt.Fprint(conn, "ping")
	buf := make([]byte, 4)
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("echo: %q %v", buf, err)
	}
	conn.Close()
	if conn, err := c.Dial("tcp", "192.0.2.1:80"); err == nil {
		conn.Close()
		t.Fatal("forward to another host allowed")
	}
}

func TestTerminalSession(t *testing.T) {
	c := start(t).client(t)
	s, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.RequestPty("xterm", 30, 100, gossh.TerminalModes{}); err != nil {
		t.Fatal(err)
	}
	in, _ := s.StdinPipe()
	var out safeBuffer
	s.Stdout, s.Stderr = &out, &out
	if err := s.Shell(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(3 * time.Second)
	_, _ = in.Write([]byte(pick("echo pty-$((40+2))\n", "Write-Output \"pty-$(40+2)\"\r")))
	time.Sleep(2 * time.Second)
	_, _ = in.Write([]byte(pick("exit 5\n", "exit 5\r")))
	done := make(chan error, 1)
	go func() { done <- s.Wait() }()
	select {
	case err := <-done:
		var ee *gossh.ExitError
		if !errors.As(err, &ee) || ee.ExitStatus() != 5 {
			t.Fatalf("terminal ended with %v, want exit 5; output %q", err, out.String())
		}
	case <-time.After(30 * time.Second):
		t.Fatalf("terminal did not exit; output %q", out.String())
	}
	if !strings.Contains(out.String(), "pty-42") {
		t.Fatalf("terminal output %q lacks pty-42", out.String())
	}
}

type safeBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *safeBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}
func (s *safeBuffer) String() string { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

func TestDisconnectEndsTheRunningCommand(t *testing.T) {
	h := start(t)
	c, err := h.dialCert(t, nil)
	if err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(h.home, "still-running")
	s, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	cmd := pick("sleep 4; touch still-running", "Start-Sleep -Seconds 4; New-Item -ItemType File still-running | Out-Null")
	if err := s.Start(cmd); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Second)
	c.Close()
	time.Sleep(6 * time.Second)
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("the command kept running after the client disconnected")
	}
}

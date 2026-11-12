// Package sshd is the device's own SSH server (docs/adr/0002-own-ssh-server.md): charm.land/ssh (BSD-3, a fork of
// gliderlabs/ssh) with a real terminal (ConPTY through charmbracelet/x/conpty on Windows, a Unix PTY elsewhere),
// pkg/sftp (BSD-2) in-process, and local port forwarding to services on this computer. It listens on the device's
// NetBird address only. Every session runs as the account the client runs as, on the whole computer (R58): no user
// switching, no administrator rights. A login is an AgentCompute SSH user certificate (certs.go); the former token
// password (legacy_token.go) stays until AgentHost moved (AgentHost#385).
package sshd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"time"

	"charm.land/ssh"
	gossh "golang.org/x/crypto/ssh"

	"github.com/agentrouter-top/AgentDevice/client/internal/facts"
	"github.com/pkg/sftp"
)

// Config is the server's setup.
type Config struct {
	HostKey gossh.Signer
	// Certificates checks certificate logins (compute/v1 README §3).
	Certificates *CertAuthority
	// Authorizer, when set, also takes the former token password. LEGACY: delete with legacy_token.go (AgentHost#385).
	Authorizer *Authorizer
	Shell      facts.UserShellInfo
	// BaseEnv is the environment commands start with (on Unix the account's login environment; see LoginEnv).
	BaseEnv []string
	// Home is where sessions and SFTP start.
	Home    string
	Version string
	Log     *slog.Logger
	// Activity, when set, receives one entry per command, terminal, SFTP session and forward (the visible log).
	Activity func(Activity)
}

// Server is one SSH server; Serve may be called again with a new listener after the network restarts.
type Server struct {
	cfg Config
	srv *ssh.Server
}

// New builds the server.
func New(cfg Config) (*Server, error) {
	if cfg.HostKey == nil || cfg.Certificates == nil || cfg.Certificates.Keys == nil {
		return nil, errors.New("sshd: a host key and the certificate authority are required")
	}
	if cfg.Certificates.ComputerID == "" || cfg.Certificates.Own == "" {
		return nil, errors.New("sshd: the certificate authority needs this computer's id and owner")
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	if cfg.Home == "" {
		cfg.Home, _ = os.UserHomeDir()
	}
	if cfg.BaseEnv == nil {
		cfg.BaseEnv = os.Environ()
	}
	s := &Server{cfg: cfg}
	srv := &ssh.Server{
		Version:                     "AgentDevice_" + strings.ReplaceAll(cfg.Version, " ", "_"),
		HandshakeTimeout:            30 * time.Second,
		Handler:                     s.handleSession,
		PublicKeyHandler:            s.publicKey,
		LocalPortForwardingCallback: s.allowForward,
		ChannelHandlers: map[string]ssh.ChannelHandler{
			"session":      ssh.DefaultSessionHandler,
			"direct-tcpip": ssh.DirectTCPIPHandler,
		},
		SubsystemHandlers: map[string]ssh.SubsystemHandler{"sftp": s.handleSFTP},
	}
	if cfg.Authorizer != nil {
		srv.PasswordHandler = s.legacyPassword // LEGACY (legacy_token.go)
	}
	srv.AddHostKey(cfg.HostKey)
	if err := srv.SetOption(ssh.AllocatePty()); err != nil {
		return nil, fmt.Errorf("sshd: %w", err)
	}
	s.srv = srv
	return s, nil
}

// Serve accepts connections on ln until it fails or Close is called.
func (s *Server) Serve(ln net.Listener) error {
	err := s.srv.Serve(ln)
	if errors.Is(err, ssh.ErrServerClosed) {
		return nil
	}
	return err
}

// Close stops the server and its connections.
func (s *Server) Close() error { return s.srv.Close() }

// allowForward allows direct-tcpip (local forwarding, `ssh -L`) only to services on this computer itself: loopback
// addresses and localhost. That is how a named endpoint (compute/v1 endpoints) reaches the program behind it; the
// device is never a way into the person's other networks.
func (s *Server) allowForward(ctx ssh.Context, host string, port uint32) bool {
	ok := isLoopback(host)
	target := net.JoinHostPort(host, fmt.Sprint(port))
	s.cfg.Log.Info("ssh forward", "remote", ctx.RemoteAddr().String(), "to", target, "allowed", ok)
	s.report(ctx, Activity{Kind: "forward", Target: target, Allowed: ok})
	return ok
}

func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	addr, err := netip.ParseAddr(strings.Trim(host, "[]"))
	return err == nil && addr.IsLoopback()
}

func (s *Server) handleSFTP(sess ssh.Session) {
	s.cfg.Log.Info("sftp start", "remote", sess.RemoteAddr().String())
	start := time.Now()
	defer func() { s.report(sess.Context(), Activity{Kind: "sftp", Seconds: time.Since(start).Seconds()}) }()
	srv, err := sftp.NewServer(sess, sftp.WithServerWorkingDirectory(s.cfg.Home))
	if err != nil {
		fmt.Fprintf(sess.Stderr(), "AgentDevice sftp: start the SFTP server: %v\n", err)
		_ = sess.Exit(1)
		return
	}
	if err := srv.Serve(); err != nil && !errors.Is(err, io.EOF) {
		s.cfg.Log.Warn("sftp ended", "remote", sess.RemoteAddr().String(), "error", err.Error())
	}
	_ = srv.Close()
	_ = sess.Exit(0)
}

// env is the environment of a session's command: the base environment, then what the client sent (env requests),
// then the SSH variables.
func (s *Server) env(sess ssh.Session, term string) []string {
	env := append([]string{}, s.cfg.BaseEnv...)
	env = append(env, sess.Environ()...)
	if ra, ok := sess.RemoteAddr().(*net.TCPAddr); ok {
		if la, ok := sess.LocalAddr().(*net.TCPAddr); ok {
			env = append(env,
				fmt.Sprintf("SSH_CONNECTION=%s %d %s %d", ra.IP, ra.Port, la.IP, la.Port),
				fmt.Sprintf("SSH_CLIENT=%s %d %d", ra.IP, ra.Port, la.Port))
		}
	}
	if term != "" {
		env = append(env, "TERM="+term)
	}
	return env
}

// handleSession runs exec and shell requests, with or without a terminal.
func (s *Server) handleSession(sess ssh.Session) {
	raw := sess.RawCommand()
	ptyReq, _, isPty := sess.Pty()
	log := s.cfg.Log.With("remote", sess.RemoteAddr().String(), "pty", isPty)
	if c := callerOf(sess.Context()); c != nil {
		log = log.With("method", c.Method, "own", c.Own, "sub", c.Sub, "run", c.Run)
		if c.Method == "certificate" {
			log = log.With("serial", c.Serial, "keyId", c.KeyID)
		}
	}
	file := ""
	if raw != "" {
		f, err := textFile(runDir(), raw)
		if err != nil {
			fail(sess, "AgentDevice ssh: could not hand the command to the shell (%v); the command did not run. Retry; if it keeps failing, check free space in %s.", err, runDir())
			return
		}
		file = f
		defer os.Remove(file) // the runner removes it first thing; this covers a shell that never started
	}
	args := argv(s.cfg.Shell, runtime.GOOS == "windows", isPty, file)
	log.Info("ssh session", "shell", s.cfg.Shell.Path, "command_bytes", len(raw))
	term := ""
	if isPty {
		term = ptyReq.Term
	}
	start := time.Now()
	code := s.run(sess, args, s.env(sess, term), isPty, ptyReq)
	log.Info("ssh session ended", "exit", code, "seconds", time.Since(start).Seconds())
	kind := "exec"
	if isPty {
		kind = "terminal"
	}
	s.report(sess.Context(), Activity{Kind: kind, Command: FirstLine(raw), Exit: code, Seconds: time.Since(start).Seconds()})
	_ = sess.Exit(code)
}

func fail(sess ssh.Session, format string, args ...any) {
	fmt.Fprintf(sess.Stderr(), format+"\n", args...)
	_ = sess.Exit(255)
}

// signals forwards the client's signal requests to tree until done is closed.
func forwardSignals(sess ssh.Session, signal func(string) error, done <-chan struct{}) {
	ch := make(chan ssh.Signal, 8)
	sess.Signals(ch)
	go func() {
		defer sess.Signals(nil)
		for {
			select {
			case sig := <-ch:
				_ = signal(string(sig))
			case <-done:
				return
			}
		}
	}()
}

// waitOrKill ends the tree when the client goes away before the command has finished.
func waitOrKill(ctx context.Context, kill func() error, done <-chan struct{}) {
	go func() {
		select {
		case <-ctx.Done():
			_ = kill()
		case <-done:
		}
	}()
}

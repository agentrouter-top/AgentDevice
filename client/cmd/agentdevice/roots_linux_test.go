package main

import (
	"crypto/x509"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
)

// A Linux system without a CA bundle still gets roots (roots.go): the test runs itself again with the system's
// certificate file and directory pointing at nothing, so crypto/x509 finds no system roots and must use the fallback.
func TestRootsWithoutASystemBundle(t *testing.T) {
	if os.Getenv("AGENTDEVICE_ROOTS_CHILD") == "1" {
		pool, err := x509.SystemCertPool()
		if err != nil {
			t.Fatalf("no root pool: %v", err)
		}
		//nolint:staticcheck // Subjects is the one way to count a pool's roots
		os.Stdout.WriteString("roots=" + strconv.Itoa(len(pool.Subjects())) + "\n")
		return
	}
	empty := t.TempDir()
	cmd := exec.Command(os.Args[0], "-test.run=^TestRootsWithoutASystemBundle$")
	cmd.Env = append(os.Environ(), "AGENTDEVICE_ROOTS_CHILD=1", "SSL_CERT_FILE="+empty+"/none.pem", "SSL_CERT_DIR="+empty)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("child: %v\n%s", err, out)
	}
	var n int
	for _, line := range strings.Split(string(out), "\n") {
		if v, ok := strings.CutPrefix(line, "roots="); ok {
			n, _ = strconv.Atoi(v)
		}
	}
	if n < 100 {
		t.Fatalf("a system without a CA bundle has %d roots, want Go's fallback set (over 100):\n%s", n, out)
	}
}

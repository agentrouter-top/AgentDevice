package compute

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/agentrouter-top/AgentDevice/client/internal/facts"
)

const testCredential = "cenr_0123456789ab_0123456789012345678901234567890123456789"

func joinCode(text string) string {
	return JoinCodePrefix + base64.RawURLEncoding.EncodeToString([]byte(text))
}

func TestParseJoinCode(t *testing.T) {
	base, cred, err := ParseJoinCode("  " + joinCode("https://compute.example.com "+testCredential) + "\n")
	if err != nil || base != "https://compute.example.com" || cred != testCredential {
		t.Fatalf("got %q %q %v", base, cred, err)
	}
	if base, _, err := ParseJoinCode(joinCode("http://127.0.0.1:8080 " + testCredential)); err != nil || base != "http://127.0.0.1:8080" {
		t.Fatalf("loopback http: %q %v", base, err)
	}
	for name, code := range map[string]string{
		"not a code":       "ckey_0123456789ab_0123456789012345678901234567890123456789",
		"not base64":       JoinCodePrefix + "!!!",
		"no credential":    joinCode("https://compute.example.com"),
		"cut credential":   joinCode("https://compute.example.com " + testCredential[:40]),
		"plain http":       joinCode("http://compute.example.com " + testCredential),
		"path in address":  joinCode("https://compute.example.com/v1 " + testCredential),
		"user in address":  joinCode("https://a@compute.example.com " + testCredential),
		"query in address": joinCode("https://compute.example.com?x=1 " + testCredential),
	} {
		_, _, err := ParseJoinCode(code)
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		// An error never repeats the credential.
		if strings.Contains(err.Error(), testCredential[18:]) || strings.Contains(err.Error(), code) {
			t.Errorf("%s: the error repeats the code: %v", name, err)
		}
	}
}

// An enrolment with a code's credential: the credential is the Bearer, the answer's deviceKey is read.
func TestEnrolWithACodeAnswersTheDeviceKey(t *testing.T) {
	const deviceKey = "ckey_abcdefghijkl_0123456789012345678901234567890123456789"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/devices" || r.Header.Get("Authorization") != "Bearer "+testCredential || r.Header.Get("Idempotency-Key") != "k1" {
			w.Header().Set("Content-Type", "application/problem+json")
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]any{"code": "COMPUTE_KEY_INVALID", "status": 401})
			return
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"computer":  map[string]any{"id": "cmp_1", "kind": "device", "name": "pc", "own": "acc_a", "state": "starting"},
			"network":   map[string]any{"managementUrl": "https://netbird.example.com", "deviceName": "cmp_1", "join": map[string]any{"method": "setup-key", "setupKey": "SK"}},
			"deviceKey": deviceKey,
		})
	}))
	defer srv.Close()
	base, cred, err := ParseJoinCode(joinCode(srv.URL + " " + testCredential))
	if err != nil {
		t.Fatal(err)
	}
	c := &Client{BaseURL: base}
	en, err := c.Enrol(context.Background(), cred, "k1", EnrolRequest{Name: "pc"})
	if err != nil {
		t.Fatal(err)
	}
	if en.DeviceKey != deviceKey || en.Computer.ID != "cmp_1" || en.Network.Join.SetupKey != "SK" {
		t.Fatalf("enrolment: %+v", en)
	}
	// A key compute/v1 no longer knows is how a device learns it was removed.
	if err := c.ReportFacts(context.Background(), "ckey_gone", "cmp_1", facts.Facts{}); !IsKeyRefused(err) || IsComputerGone(err) {
		t.Fatalf("a refused key: %v", err)
	}
}

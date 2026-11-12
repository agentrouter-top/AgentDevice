package state

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestConfigSelectsTheZitadelLogin(t *testing.T) {
	d := Dir(t.TempDir())
	write := func(s string) {
		t.Helper()
		if err := os.WriteFile(d.Path("config.json"), []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// No zitadel: the NewAPI device login, no exchange endpoint.
	write(`{"issuer":"https://newapi.test/","computeUrl":"https://compute.test"}`)
	c, err := d.LoadConfig()
	if err != nil || c.Zitadel != nil || c.ExchangeURL != "" || c.Validate("config.json") != nil {
		t.Fatalf("legacy config %+v, %v", c, err)
	}
	// zitadel: the exchange defaults to the issuer (the STS); the JWKS stays the issuer's.
	write(`{"issuer":"https://sts.test/","computeUrl":"https://compute.test","zitadel":{"url":"https://login.test/","projectId":"1","clientId":"2"}}`)
	c, err = d.LoadConfig()
	if err != nil || c.Validate("config.json") != nil {
		t.Fatalf("zitadel config: %v / %v", err, c.Validate("config.json"))
	}
	if c.Zitadel.URL != "https://login.test" || c.ExchangeURL != "https://sts.test/v1/identity/exchange" || c.JWKSURL != "https://sts.test/.well-known/jwks.json" {
		t.Fatalf("zitadel config %+v %+v", c, *c.Zitadel)
	}
	write(`{"issuer":"https://sts.test","computeUrl":"https://compute.test","zitadel":{"url":"https://login.test"}}`)
	c, _ = d.LoadConfig()
	if err := c.Validate("config.json"); err == nil || !strings.Contains(err.Error(), "zitadel.clientId, zitadel.projectId") {
		t.Fatalf("want the missing ids named, got %v", err)
	}
}

func TestConfigLayersTheInstalledEnvironment(t *testing.T) {
	d := Dir(t.TempDir())
	env := Dir(t.TempDir()).Path("environment.json")
	was := EnvironmentFile
	EnvironmentFile = func() string { return env }
	t.Cleanup(func() { EnvironmentFile = was })
	if err := os.WriteFile(env, []byte(`{"environment":"dev","issuer":"https://sts.test","computeUrl":"https://compute.test",
		"zitadel":{"url":"https://login.test","projectId":"1","clientId":"2"},"updateUrl":"https://up.test/latest","downloadUrl":"https://dl.test/setup.exe"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	// The environment alone is a complete configuration.
	c, err := d.LoadConfig()
	if err != nil || c.Validate("config.json") != nil {
		t.Fatalf("environment only: %v / %v", err, c.Validate("config.json"))
	}
	if c.Environment != "dev" || c.UpdateURL != "https://up.test/latest" || c.DownloadURL != "https://dl.test/setup.exe" || c.ExchangeURL != "https://sts.test/v1/identity/exchange" {
		t.Fatalf("environment only: %+v", c)
	}
	// config.json wins key by key; what it leaves out stays the environment's.
	if err := os.WriteFile(d.Path("config.json"), []byte(`{"computeUrl":"https://other.test/","updateUrl":""}`), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err = d.LoadConfig()
	if err != nil || c.ComputeURL != "https://other.test" || c.Issuer != "https://sts.test" || c.UpdateURL != "" || c.Zitadel == nil || c.Zitadel.ClientID != "2" {
		t.Fatalf("override: %+v, %v", c, err)
	}
	// An environment file that is not JSON is named.
	if err := os.WriteFile(env, []byte(`{`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := d.LoadConfig(); err == nil || !strings.Contains(err.Error(), "environment.json") {
		t.Fatalf("want the environment file named, got %v", err)
	}
}

func TestRemoveAllEmptiesTheFolder(t *testing.T) {
	d := Dir(t.TempDir() + "/AgentDevice")
	if err := d.Ensure(); err != nil {
		t.Fatal(err)
	}
	if err := d.SaveRefresh("r"); err != nil {
		t.Fatal(err)
	}
	if err := d.RemoveAll(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(string(d)); !os.IsNotExist(err) {
		t.Fatalf("folder still there: %v", err)
	}
}

// The environments the release lane ships (release/environments/) are files this program reads: only keys it knows
// (plus "missing", the note of an incomplete one), Dev complete, production incomplete until its names exist.
func TestShippedEnvironments(t *testing.T) {
	known := map[string]bool{"missing": true}
	for _, f := range reflect.VisibleFields(reflect.TypeOf(Config{})) {
		known[strings.Split(f.Tag.Get("json"), ",")[0]] = true
	}
	files, _ := filepath.Glob("../../../release/environments/*.json")
	if len(files) < 2 {
		t.Fatalf("release/environments has %v", files)
	}
	for _, file := range files {
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		var keys map[string]json.RawMessage
		if err := json.Unmarshal(raw, &keys); err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		for k := range keys {
			if !known[k] {
				t.Errorf("%s: key %q is not read by the client (state.Config)", file, k)
			}
		}
		was := EnvironmentFile
		EnvironmentFile = func() string { return file }
		c, err := Dir(t.TempDir()).LoadConfig()
		EnvironmentFile = was
		if err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		name := strings.TrimSuffix(filepath.Base(file), ".json")
		if c.Environment != name {
			t.Errorf("%s: environment %q, want %q", file, c.Environment, name)
		}
		complete := c.Validate("config.json") == nil && c.UpdateURL != "" && c.DownloadURL != ""
		_, incomplete := keys["missing"]
		if complete == incomplete {
			t.Errorf("%s: complete %v but \"missing\" present %v (an incomplete environment says why; a complete one does not)", file, complete, incomplete)
		}
		if name == "dev" && !complete {
			t.Errorf("dev must be complete: %v", c.Validate("config.json"))
		}
	}
}

// A device that joined with an enrolment code keeps its own key in an owner-only file; Forget removes it.
func TestDeviceKeyIsKeptPrivateAndForgotten(t *testing.T) {
	d := Dir(t.TempDir())
	if k, err := d.LoadDeviceKey(); err != nil || k != "" {
		t.Fatalf("no key yet: %q %v", k, err)
	}
	if err := d.SaveDeviceKey("ckey_abcdefghijkl_0123456789012345678901234567890123456789"); err != nil {
		t.Fatal(err)
	}
	if k, _ := d.LoadDeviceKey(); k != "ckey_abcdefghijkl_0123456789012345678901234567890123456789" {
		t.Fatalf("read back %q", k)
	}
	if fi, err := os.Stat(d.Path("device_key")); err != nil || (runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600) {
		t.Fatalf("device_key mode: %v %v", fi, err)
	}
	if err := d.SaveDevice(&Device{ComputerID: "cmp_1", Own: "acc_a", ComputeURL: "https://compute.example.com"}); err != nil {
		t.Fatal(err)
	}
	if dev, _ := d.LoadDevice(); dev == nil || dev.ComputeURL != "https://compute.example.com" {
		t.Fatalf("device.json computeUrl: %+v", dev)
	}
	if err := d.Forget(); err != nil {
		t.Fatal(err)
	}
	if k, _ := d.LoadDeviceKey(); k != "" {
		t.Fatal("the device key outlived Forget")
	}
}

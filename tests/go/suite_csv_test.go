package testfw

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadCSUMSuite(t *testing.T) {
	suiteDir := filepath.Join("..", "csum")
	tests, err := LoadTests(filepath.Join(suiteDir, "tests.csv"))
	if err != nil {
		t.Fatalf("LoadTests: %v", err)
	}
	if len(tests) != 14 {
		t.Fatalf("loaded %d tests, want 14", len(tests))
	}

	for _, test := range tests {
		assertProgramSourceExists(t, suiteDir, test.ServerProg)
		assertProgramSourceExists(t, suiteDir, test.ServerEgressProg)
		assertProgramSourceExists(t, suiteDir, test.ClientProg)
	}
}

func TestLoadAllSuites(t *testing.T) {
	entries, err := os.ReadDir("..")
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		suiteDir := filepath.Join("..", entry.Name())
		csvPath := filepath.Join(suiteDir, "tests.csv")
		if _, err := os.Stat(csvPath); err != nil {
			continue
		}
		t.Run(entry.Name(), func(t *testing.T) {
			tests, err := LoadTests(csvPath)
			if err != nil {
				t.Fatalf("LoadTests: %v", err)
			}
			for _, test := range tests {
				assertProgramSourceExists(t, suiteDir, test.ServerProg)
				assertProgramSourceExists(t, suiteDir, test.ServerEgressProg)
				assertProgramSourceExists(t, suiteDir, test.ClientProg)
			}
		})
	}
}

func TestLoadConfigsDefaultsAndOverlay(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "base.ini")
	override := filepath.Join(dir, "override.ini")

	baseConfig := []byte("[machine_a]\nip4 = 10.0.0.1\niface = eth-a\n\n[test]\ntimeout = 7.5\nverify_timeout = 11.25\nverify_policy = fail\n")
	if err := os.WriteFile(base, baseConfig, 0644); err != nil {
		t.Fatalf("WriteFile base: %v", err)
	}
	overrideConfig := []byte("[machine_a]\niface = eth-override\n\n[test]\nsleep = 250\n")
	if err := os.WriteFile(override, overrideConfig, 0644); err != nil {
		t.Fatalf("WriteFile override: %v", err)
	}

	cfg, err := LoadConfigs(filepath.Join(dir, "missing.ini"), base, override)
	if err != nil {
		t.Fatalf("LoadConfigs: %v", err)
	}
	if cfg.MachineA.IP4 != "10.0.0.1" {
		t.Fatalf("MachineA.IP4 = %q, want 10.0.0.1", cfg.MachineA.IP4)
	}
	if cfg.MachineA.Iface != "eth-override" {
		t.Fatalf("MachineA.Iface = %q, want eth-override", cfg.MachineA.Iface)
	}
	if cfg.Test.SleepMs != 250 {
		t.Fatalf("SleepMs = %d, want 250", cfg.Test.SleepMs)
	}
	if cfg.Test.Timeout != 7.5 {
		t.Fatalf("Timeout = %v, want 7.5", cfg.Test.Timeout)
	}
	if cfg.Test.VerifyTimeout != 11.25 {
		t.Fatalf("VerifyTimeout = %v, want 11.25", cfg.Test.VerifyTimeout)
	}
	if cfg.Test.VerifyPolicy != VerifyPolicyFail {
		t.Fatalf("VerifyPolicy = %q, want %q", cfg.Test.VerifyPolicy, VerifyPolicyFail)
	}
}

func TestProtocolMessages(t *testing.T) {
	tests := []Test{{
		Name:          "sample",
		ServerProg:    "sample.o",
		ServerType:    "xdp",
		Proto:         "udp",
		Family:        4,
		PaddedPayload: true,
		Expected:      "packet_reaches_port_8888",
	}}
	manifest := TestManifestID(tests)

	gotManifest, gotIPv6, err := ParseHello(FormatHello(manifest, true))
	if err != nil {
		t.Fatalf("ParseHello: %v", err)
	}
	if gotManifest != manifest || !gotIPv6 {
		t.Fatalf("ParseHello = (%q, %v), want (%q, true)", gotManifest, gotIPv6, manifest)
	}

	if ok, err := ParseHelloOK(FormatHelloOK(false)); err != nil || ok {
		t.Fatalf("ParseHelloOK = (%v, %v), want (false, nil)", ok, err)
	}

	blocked := map[string]string{"sample": "server_verify_failed"}
	parsedBlocked, err := ParseVerifyBlocked(FormatVerifyBlocked(blocked))
	if err != nil {
		t.Fatalf("ParseVerifyBlocked: %v", err)
	}
	if parsedBlocked["sample"] != "server_verify_failed" {
		t.Fatalf("VERIFY parse = %q, want server_verify_failed", parsedBlocked["sample"])
	}

	name, _, ok := ParseNamedControl(FormatReady("sample"), "READY:")
	if !ok || name != "sample" {
		t.Fatalf("READY parse = (%q, %v), want sample true", name, ok)
	}

	name, reason, ok := ParseNamedControl(FormatSkip("sample", "ipv6_unavailable"), "SKIP:")
	if !ok || name != "sample" || reason != "ipv6_unavailable" {
		t.Fatalf("SKIP parse = (%q, %q, %v)", name, reason, ok)
	}

	name, reason, ok = ParseNamedControl(FormatUnverified("sample", "server_verify_failed"), "UNVERIFIED:")
	if !ok || name != "sample" || reason != "server_verify_failed" {
		t.Fatalf("UNVERIFIED parse = (%q, %q, %v)", name, reason, ok)
	}

	name, status, ok := ParseResult(FormatResult("sample", "OK"))
	if !ok || name != "sample" || status != "OK" {
		t.Fatalf("RESULT parse = (%q, %q, %v)", name, status, ok)
	}
}

func assertProgramSourceExists(t *testing.T, suiteDir, prog string) {
	t.Helper()
	if prog == "" {
		return
	}
	src := strings.TrimSuffix(prog, filepath.Ext(prog)) + ".c"
	if _, err := os.Stat(filepath.Join(suiteDir, src)); err != nil {
		t.Fatalf("%s declares %s but source %s was not found: %v", filepath.Join(suiteDir, "tests.csv"), prog, src, err)
	}
}

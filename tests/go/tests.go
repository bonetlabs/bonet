package testfw

import (
	"crypto/sha256"
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
)

// Test describes a single test case loaded from a suite CSV file.
type Test struct {
	Name             string
	Description      string
	Expected         string
	ServerProg       string // .o file loaded on Machine B TC ingress (or XDP)
	ServerType       string // "tc-ingress" | "xdp"
	ServerEgressProg string // .o file loaded on Machine B TC egress, or ""
	ServerEgressType string // "tc-egress" | ""
	ClientProg       string // .o file loaded on Machine A TC egress, or ""
	ClientType       string // "tc-egress" | ""
	Proto            string // traffic generator name ("tcp", "udp", "icmp4", "icmp6", "arp", raw crafted variants)
	Family           int    // 4 | 6
	PaddedPayload    bool   // send PaddingLen trailing bytes
}

// LoadTests reads test cases from a CSV file.
func LoadTests(path string) ([]Test, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	r := csv.NewReader(f)
	r.Comment = '#'
	r.FieldsPerRecord = -1
	r.TrimLeadingSpace = true

	header, err := r.Read()
	if err != nil {
		return nil, fmt.Errorf("read CSV header: %w", err)
	}

	columns := map[string]int{}
	for i, col := range header {
		columns[normalizeCSVColumn(col)] = i
	}

	for _, col := range []string{
		"name",
		"server_prog",
		"server_type",
		"server_egress_prog",
		"server_egress_type",
		"client_prog",
		"client_type",
		"proto",
		"family",
	} {
		if _, ok := columns[col]; !ok {
			return nil, fmt.Errorf("missing required CSV column %q", col)
		}
	}

	var tests []Test
	line := 1
	for {
		record, err := r.Read()
		if err == io.EOF {
			break
		}
		line++
		if err != nil {
			return nil, fmt.Errorf("read CSV line %d: %w", line, err)
		}

		value := func(name string) string {
			idx, ok := columns[name]
			if !ok || idx >= len(record) {
				return ""
			}
			return strings.TrimSpace(record[idx])
		}

		name := value("name")
		if name == "" {
			continue
		}

		family, err := strconv.Atoi(value("family"))
		if err != nil || (family != 4 && family != 6) {
			return nil, fmt.Errorf("line %d: invalid family %q", line, value("family"))
		}

		proto := strings.ToLower(value("proto"))
		if !isValidProto(proto) {
			return nil, fmt.Errorf("line %d: invalid proto %q", line, value("proto"))
		}

		test := Test{
			Name:             name,
			Description:      value("description"),
			Expected:         value("expected"),
			ServerProg:       value("server_prog"),
			ServerType:       value("server_type"),
			ServerEgressProg: value("server_egress_prog"),
			ServerEgressType: value("server_egress_type"),
			ClientProg:       value("client_prog"),
			ClientType:       value("client_type"),
			Proto:            proto,
			Family:           family,
			PaddedPayload:    strings.Contains(name, "adjust"),
		}

		if test.ServerProg == "" {
			return nil, fmt.Errorf("line %d: server_prog is required", line)
		}
		if (test.ServerEgressProg == "") != (test.ServerEgressType == "") {
			return nil, fmt.Errorf("line %d: server_egress_prog and server_egress_type must be set together", line)
		}
		if (test.ClientProg == "") != (test.ClientType == "") {
			return nil, fmt.Errorf("line %d: client_prog and client_type must be set together", line)
		}
		if err := validateProgType("server_type", test.ServerType, true); err != nil {
			return nil, fmt.Errorf("line %d: %w", line, err)
		}
		if err := validateProgType("server_egress_type", test.ServerEgressType, test.ServerEgressProg != ""); err != nil {
			return nil, fmt.Errorf("line %d: %w", line, err)
		}
		if err := validateProgType("client_type", test.ClientType, test.ClientProg != ""); err != nil {
			return nil, fmt.Errorf("line %d: %w", line, err)
		}

		if _, ok := columns["padded_payload"]; ok {
			test.PaddedPayload, err = parseCSVBool(value("padded_payload"))
			if err != nil {
				return nil, fmt.Errorf("line %d: padded_payload: %w", line, err)
			}
		}

		tests = append(tests, test)
	}

	if len(tests) == 0 {
		return nil, fmt.Errorf("no tests found in %s", path)
	}
	return tests, nil
}

// WantsPacketResult reports whether the server should observe a packet at PortTo.
func (t Test) WantsPacketResult() bool {
	expected := normalizeExpectation(t.Expected)
	return expected == "" ||
		strings.Contains(expected, "reaches_port_8888") ||
		strings.Contains(expected, "packet_reaches") ||
		strings.Contains(expected, "tcp_handshake_reaches")
}

// WantsDropResult reports whether the server should verify that no packet reaches PortTo.
func (t Test) WantsDropResult() bool {
	return strings.Contains(normalizeExpectation(t.Expected), "packet_dropped")
}

// WantsMapResult reports whether the BPF program should write bnt_test_result.
func (t Test) WantsMapResult() bool {
	return strings.Contains(normalizeExpectation(t.Expected), "map_status_ok")
}

func normalizeExpectation(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

func isValidProto(proto string) bool {
	switch proto {
	case "tcp", "udp", "icmp4", "icmp6", "arp",
		"vlan1-udp4", "vlan2-udp4",
		"udp4-frag", "udp4-frag-nonfirst",
		"udp6-frag", "udp6-frag-nonfirst",
		"ipv6-ext-icmp6", "ipv6-too-deep",
		"mpls1-udp4", "mpls2-udp4", "mpls1-udp6",
		"ipip-udp4", "ipv6inipv4-udp", "ipv4inipv6-udp",
		"srv6encap-udp4":
		return true
	default:
		return false
	}
}

func normalizeCSVColumn(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

func validateProgType(column, typ string, required bool) error {
	if typ == "" {
		if required {
			return fmt.Errorf("%s is required", column)
		}
		return nil
	}
	switch typ {
	case "tc-ingress", "tc-egress", "xdp":
		return nil
	default:
		return fmt.Errorf("invalid %s %q", column, typ)
	}
}

func parseCSVBool(s string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "0", "false", "no", "n":
		return false, nil
	case "1", "true", "yes", "y":
		return true, nil
	default:
		return false, fmt.Errorf("invalid boolean %q", s)
	}
}

const (
	StatusOK         = "OK"
	StatusFail       = "FAIL"
	StatusSkip       = "SKIP"
	StatusUnverified = "UNVERIFIED"
)

const ProtocolVersion = "bonet-test-v1"

// TestManifestID returns a stable identifier for the behavior-relevant suite
// content. Client and server exchange it before running so stale CSV files fail
// early instead of desynchronizing mid-suite.
func TestManifestID(tests []Test) string {
	h := sha256.New()
	for _, t := range tests {
		fmt.Fprintf(h, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%d\t%t\t%s\n",
			t.Name,
			t.ServerProg,
			t.ServerType,
			t.ServerEgressProg,
			t.ServerEgressType,
			t.ClientProg,
			t.ClientType,
			t.Proto,
			t.Family,
			t.PaddedPayload,
			normalizeExpectation(t.Expected),
		)
	}
	sum := h.Sum(nil)
	return fmt.Sprintf("%x", sum[:16])
}

func FormatHello(manifest string, ipv6OK bool) string {
	return fmt.Sprintf("HELLO:%s:%s:%s\n", ProtocolVersion, manifest, boolToken(ipv6OK))
}

func ParseHello(line string) (manifest string, ipv6OK bool, err error) {
	line = strings.TrimSpace(line)
	parts := strings.SplitN(line, ":", 4)
	if len(parts) != 4 || parts[0] != "HELLO" {
		return "", false, fmt.Errorf("expected HELLO, got %q", line)
	}
	if parts[1] != ProtocolVersion {
		return "", false, fmt.Errorf("protocol mismatch: got %q want %q", parts[1], ProtocolVersion)
	}
	ipv6OK, err = parseBoolToken(parts[3])
	if err != nil {
		return "", false, fmt.Errorf("invalid HELLO IPv6 flag: %w", err)
	}
	return parts[2], ipv6OK, nil
}

func FormatHelloOK(ipv6OK bool) string {
	return fmt.Sprintf("HELLO-OK:%s\n", boolToken(ipv6OK))
}

func ParseHelloOK(line string) (bool, error) {
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "HELLO-OK:") {
		return false, fmt.Errorf("expected HELLO-OK, got %q", line)
	}
	return parseBoolToken(strings.TrimPrefix(line, "HELLO-OK:"))
}

func FormatVerifyBlocked(blocked map[string]string) string {
	names := make([]string, 0, len(blocked))
	for name := range blocked {
		names = append(names, name)
	}
	sort.Strings(names)

	fields := make([]string, 0, len(names))
	for _, name := range names {
		fields = append(fields, sanitizeControlField(name)+"="+sanitizeControlField(blocked[name]))
	}
	return fmt.Sprintf("VERIFY:%s\n", strings.Join(fields, ","))
}

func ParseVerifyBlocked(line string) (map[string]string, error) {
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "VERIFY:") {
		return nil, fmt.Errorf("expected VERIFY, got %q", line)
	}
	out := map[string]string{}
	payload := strings.TrimPrefix(line, "VERIFY:")
	if payload == "" {
		return out, nil
	}
	for _, field := range strings.Split(payload, ",") {
		name, reason, ok := strings.Cut(field, "=")
		if !ok || name == "" {
			return nil, fmt.Errorf("invalid VERIFY field %q", field)
		}
		out[name] = reason
	}
	return out, nil
}

func MergeBlockedTests(a, b map[string]string) map[string]string {
	out := map[string]string{}
	for name, reason := range a {
		out[name] = reason
	}
	for name, reason := range b {
		if prev, ok := out[name]; ok && prev != "" && reason != "" && prev != reason {
			out[name] = prev + "+" + reason
			continue
		}
		out[name] = reason
	}
	return out
}

func FormatAbort(reason string) string {
	return fmt.Sprintf("ABORT:%s\n", sanitizeControlField(reason))
}

func FormatReady(name string) string {
	return fmt.Sprintf("READY:%s\n", sanitizeControlField(name))
}

func FormatSkip(name, reason string) string {
	return fmt.Sprintf("SKIP:%s:%s\n", sanitizeControlField(name), sanitizeControlField(reason))
}

func FormatUnverified(name, reason string) string {
	return fmt.Sprintf("UNVERIFIED:%s:%s\n", sanitizeControlField(name), sanitizeControlField(reason))
}

func ParseNamedControl(line, prefix string) (name, rest string, ok bool) {
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, prefix) {
		return "", "", false
	}
	msg := strings.TrimPrefix(line, prefix)
	if prefix == "SKIP:" || prefix == "UNVERIFIED:" {
		name, rest, ok = strings.Cut(msg, ":")
		return name, rest, ok
	}
	return msg, "", true
}

func FormatResult(name, status string) string {
	return fmt.Sprintf("RESULT:%s:%s\n", sanitizeControlField(name), sanitizeControlField(status))
}

func ParseResult(line string) (name, status string, ok bool) {
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "RESULT:") {
		return "", "", false
	}
	return strings.Cut(strings.TrimPrefix(line, "RESULT:"), ":")
}

func boolToken(v bool) string {
	if v {
		return "1"
	}
	return "0"
}

func parseBoolToken(s string) (bool, error) {
	switch strings.TrimSpace(s) {
	case "1":
		return true, nil
	case "0":
		return false, nil
	default:
		return false, fmt.Errorf("expected 0 or 1, got %q", s)
	}
}

func sanitizeControlField(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	return s
}

// Ports used by the BPF programs and the test framework.
const (
	CtrlPort   = 9990 // server listens, client connects (server sends READY)
	ResultPort = 9991 // client listens, server connects (server sends RESULT)
	PortFrom   = 7777 // BPF programs filter on this destination port
	PortTo     = 8888 // BPF programs rewrite destination port to this
	PaddingLen = 16   // payload bytes stripped by adjust tests
)

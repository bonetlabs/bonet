package testfw

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// ProgHandle identifies an attached BPF program so it can be detached later.
type ProgHandle struct {
	iface   string
	coll    *ebpf.Collection
	filter  *netlink.BpfFilter
	xdpLink link.Link
}

const (
	TestResultMagic    uint32 = 0x50545854 // "PTXT"
	TestResultStatusOK int32  = 1
)

// TestResult is the small cross-suite result record written by BPF tests that
// validate parser/debug/setter state through a map instead of packet delivery.
type TestResult struct {
	Magic    uint32
	Status   int32
	Seen     uint64
	Expected uint64
	Detail   [6]uint64
}

func (r TestResult) OK() bool {
	return r.Magic == TestResultMagic && r.Status == TestResultStatusOK
}

// LoadProg loads a BPF object and attaches it to iface.
// progType is "tc-ingress", "tc-egress", or "xdp".
// sleepMs is a post-attach settle delay (0 to skip).
func LoadProg(progDir, iface, progFile, progType string, sleepMs int) (*ProgHandle, error) {
	path := filepath.Join(progDir, progFile)
	mainName := strings.TrimSuffix(filepath.Base(progFile), ".o")

	spec, err := ebpf.LoadCollectionSpec(path)
	if err != nil {
		return nil, fmt.Errorf("load spec %s: %w", progFile, err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("new collection %s: %w", progFile, err)
	}
	keepCollection := false
	defer func() {
		if !keepCollection {
			coll.Close()
		}
	}()

	mainProg := coll.Programs[mainName]
	if mainProg == nil {
		names := availableProgramNames(coll)
		if len(names) == 0 {
			return nil, fmt.Errorf("no programs found in %s", progFile)
		}
		return nil, fmt.Errorf("program %q not found in %s (available: %s)",
			mainName, progFile, strings.Join(names, ", "))
	}

	// Populate prog_map for XDP tail-call programs.
	if pm, ok := coll.Maps["prog_map"]; ok {
		names := make([]string, 0, len(coll.Programs))
		for name := range coll.Programs {
			if name != mainName {
				names = append(names, name)
			}
		}
		sort.Strings(names)
		for i, name := range names {
			if err := pm.Put(uint32(i), coll.Programs[name]); err != nil {
				return nil, fmt.Errorf("prog_map[%d]=%s: %w", i, name, err)
			}
		}
	}

	nlLink, err := netlink.LinkByName(iface)
	if err != nil {
		return nil, fmt.Errorf("link %s: %w", iface, err)
	}
	ifindex := nlLink.Attrs().Index

	var handle *ProgHandle
	switch progType {
	case "xdp":
		xl, err := link.AttachXDP(link.XDPOptions{
			Program:   mainProg,
			Interface: ifindex,
		})
		if err != nil {
			return nil, fmt.Errorf("attach XDP on %s: %w", iface, err)
		}
		handle = &ProgHandle{iface: iface, coll: coll, xdpLink: xl}

	case "tc-ingress", "tc-egress":
		egress := progType == "tc-egress"
		handle, err = attachTC(ifindex, iface, egress, mainProg.FD(), mainName)
		if err != nil {
			return nil, err
		}
		handle.coll = coll

	default:
		return nil, fmt.Errorf("unknown prog type %q", progType)
	}

	if sleepMs > 0 {
		time.Sleep(time.Duration(sleepMs) * time.Millisecond)
	}
	keepCollection = true
	return handle, nil
}

func attachTC(ifindex int, iface string, egress bool, progFD int, progName string) (*ProgHandle, error) {
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: ifindex,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}
	if err := netlink.QdiscAdd(qdisc); err != nil && !errors.Is(err, syscall.EEXIST) {
		return nil, fmt.Errorf("qdisc add on %s: %w", iface, err)
	}

	parent := uint32(netlink.HANDLE_MIN_INGRESS)
	if egress {
		parent = uint32(netlink.HANDLE_MIN_EGRESS)
	}
	dir := "ingress"
	if egress {
		dir = "egress"
	}

	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: ifindex,
			Parent:    parent,
			Handle:    netlink.MakeHandle(0, 1),
			Priority:  1,
			Protocol:  unix.ETH_P_ALL,
		},
		Fd:           progFD,
		Name:         progName,
		DirectAction: true,
	}

	// Remove any stale filter at this slot.
	netlink.FilterDel(filter)

	if err := netlink.FilterAdd(filter); err != nil {
		return nil, fmt.Errorf("filter add on %s %s: %w", iface, dir, err)
	}
	return &ProgHandle{iface: iface, filter: filter}, nil
}

// UnloadProg detaches a previously attached BPF program.
func UnloadProg(h *ProgHandle) {
	if h == nil {
		return
	}
	if h.xdpLink != nil {
		if err := h.xdpLink.Close(); err != nil && !errors.Is(err, unix.ENOENT) {
			fmt.Printf("[warn] xdp detach on %s: %v\n", h.iface, err)
		}
	}
	if h.filter != nil {
		if err := netlink.FilterDel(h.filter); err != nil && !errors.Is(err, unix.ENOENT) {
			fmt.Printf("[warn] filter del on %s: %v\n", h.iface, err)
		}
	}
	if h.coll != nil {
		h.coll.Close()
		h.coll = nil
	}
}

// LookupTestResult reads map "bnt_test_result" when the loaded object exposes
// it. The boolean is false when the program has not reported a result yet or
// when the object does not define the map.
func (h *ProgHandle) LookupTestResult() (TestResult, bool, error) {
	var out TestResult
	if h == nil || h.coll == nil {
		return out, false, nil
	}
	m := h.coll.Maps["bnt_test_result"]
	if m == nil {
		return out, false, nil
	}
	key := uint32(0)
	if err := m.Lookup(key, &out); err != nil {
		return out, false, err
	}
	if out.Magic != TestResultMagic {
		return out, false, nil
	}
	return out, true, nil
}

// WaitForTestResult polls bnt_test_result until the BPF program reports.
func WaitForTestResult(h *ProgHandle, timeout time.Duration) (TestResult, bool, error) {
	deadline := time.Now().Add(timeout)
	for {
		result, ok, err := h.LookupTestResult()
		if err != nil || ok || time.Now().After(deadline) {
			return result, ok, err
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// ProgSpec describes a BPF program to load for verification.
type ProgSpec struct {
	File string
	Type string
}

// VerifyError records a failed verify-load.
type VerifyError struct {
	File string
	Type string
	Err  string
}

const VerifyLoadSubcommand = "__bonet_verify_load"

// RunVerifyLoadSubcommand is used by server/client binaries as an internal
// helper so slow verifier runs can be timed out without wedging the main runner.
func RunVerifyLoadSubcommand(args []string) int {
	fs := flag.NewFlagSet(VerifyLoadSubcommand, flag.ContinueOnError)
	progDir := fs.String("prog-dir", ".", "directory containing .o files")
	iface := fs.String("iface", "", "network interface")
	progFile := fs.String("prog", "", "BPF object file")
	progType := fs.String("type", "", "program attach type")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *iface == "" || *progFile == "" || *progType == "" {
		fmt.Fprintln(os.Stderr, "iface, prog and type are required")
		return 2
	}
	h, err := LoadProg(*progDir, *iface, *progFile, *progType, 0)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	UnloadProg(h)
	return 0
}

// VerifyLoad tries loading and immediately unloading each unique program.
func VerifyLoad(progDir, iface string, progs []ProgSpec) []VerifyError {
	return VerifyLoadWithTimeout(progDir, iface, progs, 0)
}

// VerifyLoadWithTimeout tries loading and immediately unloading each unique
// program. A positive timeout runs each load in an isolated subprocess.
func VerifyLoadWithTimeout(progDir, iface string, progs []ProgSpec, timeout time.Duration) []VerifyError {
	var failures []VerifyError
	seen := map[string]bool{}
	for _, ps := range progs {
		key := ProgSpecKey(ps.File, ps.Type)
		if ps.File == "" || seen[key] {
			continue
		}
		seen[key] = true
		fmt.Printf("[verify]   %s ... ", ps.File)
		err := verifyLoadOne(progDir, iface, ps, timeout)
		if err != nil {
			line := firstNonEmptyLine(err.Error())
			fmt.Printf("FAIL\n         %s\n", line)
			failures = append(failures, VerifyError{File: ps.File, Type: ps.Type, Err: line})
			continue
		}
		fmt.Println("OK")
	}
	return failures
}

func verifyLoadOne(progDir, iface string, ps ProgSpec, timeout time.Duration) error {
	if timeout <= 0 {
		h, err := LoadProg(progDir, iface, ps.File, ps.Type, 0)
		if err != nil {
			return err
		}
		UnloadProg(h)
		return nil
	}

	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("find executable for verify subprocess: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, exe,
		VerifyLoadSubcommand,
		"--prog-dir", progDir,
		"--iface", iface,
		"--prog", ps.File,
		"--type", ps.Type,
	)
	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return fmt.Errorf("verify/load timed out after %s", timeout.Round(time.Millisecond))
	}
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg != "" {
			return fmt.Errorf("%s", msg)
		}
		return err
	}
	return nil
}

func ProgSpecKey(file, typ string) string {
	return typ + "\x00" + file
}

func BlockedTestsByFailures(tests []Test, failures []VerifyError, side string) map[string]string {
	failed := map[string]bool{}
	for _, failure := range failures {
		failed[ProgSpecKey(failure.File, failure.Type)] = true
	}

	blocked := map[string]string{}
	reason := side + "_verify_failed"
	for _, test := range tests {
		switch side {
		case "server":
			if failed[ProgSpecKey(test.ServerProg, test.ServerType)] ||
				(test.ServerEgressProg != "" && failed[ProgSpecKey(test.ServerEgressProg, test.ServerEgressType)]) {
				blocked[test.Name] = reason
			}
		case "client":
			if test.ClientProg != "" && failed[ProgSpecKey(test.ClientProg, test.ClientType)] {
				blocked[test.Name] = reason
			}
		}
	}
	return blocked
}

func firstNonEmptyLine(s string) string {
	for _, line := range strings.Split(s, "\n") {
		if strings.TrimSpace(line) != "" {
			return line
		}
	}
	return s
}

func availableProgramNames(coll *ebpf.Collection) []string {
	names := make([]string, 0, len(coll.Programs))
	for name := range coll.Programs {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

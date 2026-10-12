package main

import (
	"bufio"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	testfw "bonettests"
)

var (
	activeMu     sync.Mutex
	activeHandle *testfw.ProgHandle
)

func setActive(h *testfw.ProgHandle) {
	activeMu.Lock()
	activeHandle = h
	activeMu.Unlock()
}

func clearActive() {
	activeMu.Lock()
	activeHandle = nil
	activeMu.Unlock()
}

func installSignalHandler() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-ch
		fmt.Fprintln(os.Stderr, "\n[signal] interrupted — detaching BPF program")
		activeMu.Lock()
		h := activeHandle
		activeHandle = nil
		activeMu.Unlock()
		testfw.UnloadProg(h)
		os.Exit(130)
	}()
}

func ping(host string, family int) bool {
	f := "-4"
	if family == 6 {
		f = "-6"
	}
	return exec.Command("ping", f, "-c", "1", "-W", "2", host).Run() == nil
}

func checkConnectivity(ip4, ip6 string) bool {
	fmt.Println("Checking connectivity...")
	ok4 := ping(ip4, 4)
	fmt.Printf("  IPv4 %-40s %s\n", ip4, boolStr(ok4))
	if !ok4 {
		fmt.Fprintln(os.Stderr, "ERROR: IPv4 unreachable — aborting.")
		os.Exit(1)
	}
	if ip6 == "" {
		fmt.Println("  IPv6 not configured")
		fmt.Println()
		return false
	}
	ok6 := ping(ip6, 6)
	fmt.Printf("  IPv6 %-40s %s\n", ip6, boolStr(ok6))
	fmt.Println()
	if !ok6 {
		fmt.Fprintln(os.Stderr, "WARNING: IPv6 unreachable — IPv6 tests will be skipped.")
		return false
	}
	return true
}

func boolStr(b bool) string {
	if b {
		return "OK"
	}
	return "UNREACHABLE"
}

func testPayload(padded bool) []byte {
	payload := []byte("CSUM_TEST")
	if !padded {
		return payload
	}
	return append(payload, make([]byte, testfw.PaddingLen)...)
}

func sendUDP(host string, port, family int, payload []byte) {
	network := "udp4"
	if family == 6 {
		network = "udp6"
	}
	conn, err := net.Dial(network, net.JoinHostPort(host, fmt.Sprintf("%d", port)))
	if err != nil {
		return
	}
	conn.Write(payload)
	conn.Close()
}

func sendTCP(host string, port, family int, payload []byte) {
	network := "tcp4"
	if family == 6 {
		network = "tcp6"
	}
	conn, err := (&net.Dialer{Timeout: time.Second}).Dial(network, net.JoinHostPort(host, fmt.Sprintf("%d", port)))
	if err != nil {
		return // RST or timeout expected for csum-only tests
	}
	conn.Write(payload)
	conn.Close()
}

func sendPacket(host, proto string, port, family int, padded bool, iface, srcIP4, srcIP6 string) {
	payload := testPayload(padded)
	switch proto {
	case "udp":
		sendUDP(host, port, family, payload)
	case "tcp":
		sendTCP(host, port, family, payload)
	case "icmp4", "icmp6":
		testfw.SendICMPPing(host, family)
	case "arp":
		if err := testfw.SendARPRequest(iface, srcIP4, host); err != nil {
			fmt.Printf("[warn] raw ARP send: %v\n", err)
		}
	case "vlan1-udp4":
		if err := testfw.SendVLANUDP4(iface, srcIP4, host, 1, port, port); err != nil {
			fmt.Printf("[warn] raw VLAN UDP send: %v\n", err)
		}
	case "vlan2-udp4":
		if err := testfw.SendVLANUDP4(iface, srcIP4, host, 2, port, port); err != nil {
			fmt.Printf("[warn] raw VLAN UDP send: %v\n", err)
		}
	case "udp4-frag":
		if err := testfw.SendIPv4UDPFragment(iface, srcIP4, host, port, port); err != nil {
			fmt.Printf("[warn] raw IPv4 fragment send: %v\n", err)
		}
	case "udp4-frag-nonfirst":
		if err := testfw.SendIPv4UDPNonFirstFragment(iface, srcIP4, host); err != nil {
			fmt.Printf("[warn] raw IPv4 non-first fragment send: %v\n", err)
		}
	case "udp6-frag":
		if err := testfw.SendIPv6UDPFirstFragment(iface, srcIP6, host, port, port); err != nil {
			fmt.Printf("[warn] raw IPv6 fragment send: %v\n", err)
		}
	case "udp6-frag-nonfirst":
		if err := testfw.SendIPv6UDPNonFirstFragment(iface, srcIP6, host); err != nil {
			fmt.Printf("[warn] raw IPv6 non-first fragment send: %v\n", err)
		}
	case "ipv6-ext-icmp6":
		if err := testfw.SendIPv6ExtICMP6(iface, srcIP6, host, false); err != nil {
			fmt.Printf("[warn] raw IPv6 extension send: %v\n", err)
		}
	case "ipv6-too-deep":
		if err := testfw.SendIPv6ExtICMP6(iface, srcIP6, host, true); err != nil {
			fmt.Printf("[warn] raw IPv6 too-deep send: %v\n", err)
		}
	case "mpls1-udp4":
		if err := testfw.SendMPLSUDP4(iface, srcIP4, host, 1, port); err != nil {
			fmt.Printf("[warn] raw MPLS1 UDP4 send: %v\n", err)
		}
	case "mpls2-udp4":
		if err := testfw.SendMPLSUDP4(iface, srcIP4, host, 2, port); err != nil {
			fmt.Printf("[warn] raw MPLS2 UDP4 send: %v\n", err)
		}
	case "mpls1-udp6":
		if err := testfw.SendMPLSUDP6(iface, srcIP6, host, port); err != nil {
			fmt.Printf("[warn] raw MPLS1 UDP6 send: %v\n", err)
		}
	case "ipip-udp4":
		if err := testfw.SendIPIPUDP4(iface, srcIP4, host, port); err != nil {
			fmt.Printf("[warn] raw IPIP UDP4 send: %v\n", err)
		}
	case "ipv6inipv4-udp":
		if err := testfw.SendIPv6inIPv4UDP(iface, srcIP4, host, port); err != nil {
			fmt.Printf("[warn] raw IPv6-in-IPv4 UDP send: %v\n", err)
		}
	case "ipv4inipv6-udp":
		if err := testfw.SendIPv4inIPv6UDP(iface, srcIP6, host, port); err != nil {
			fmt.Printf("[warn] raw IPv4-in-IPv6 UDP send: %v\n", err)
		}
	case "srv6encap-udp4":
		if err := testfw.SendSRv6EncapUDP4(iface, srcIP6, host, port); err != nil {
			fmt.Printf("[warn] raw SRv6 encap UDP4 send: %v\n", err)
		}
	default:
		fmt.Printf("[warn] unsupported proto %q\n", proto)
	}
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == testfw.VerifyLoadSubcommand {
		os.Exit(testfw.RunVerifyLoadSubcommand(os.Args[2:]))
	}

	var cfgPaths testfw.ConfigPaths
	flag.Var(&cfgPaths, "config", "path to config.ini (can be repeated; later files override earlier)")
	testsPath := flag.String("tests", "tests.csv", "path to suite test cases CSV")
	iface := flag.String("i", "", "network interface (Machine A)")
	serverIP := flag.String("server-ip", "", "IPv4 address of Machine B")
	serverIP6 := flag.String("server-ip6", "", "IPv6 address of Machine B (skip IPv6 tests if absent)")
	ctrlPort := flag.Int("ctrl-port", testfw.CtrlPort, "control port (server listens)")
	resultPort := flag.Int("result-port", testfw.ResultPort, "result port (we listen)")
	progDir := flag.String("prog-dir", ".", "directory containing .o files")
	sleepMs := flag.Int("sleep", 0, "post-attach sleep in ms (0 = use config)")
	verifyTimeoutSec := flag.Float64("verify-timeout", 0, "per-program verify/load timeout in seconds (0 = use config, negative = disabled)")
	verifyPolicyFlag := flag.String("verify-policy", "", "verify failure policy: fail or unverified (empty = use config)")
	keepOffloads := flag.Bool("keep-offloads", false, "skip disabling NIC offloads")
	flag.Parse()
	installSignalHandler()

	cfg, err := testfw.LoadConfigs(cfgPaths...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config: %v\n", err)
		os.Exit(1)
	}
	tests, err := testfw.LoadTests(*testsPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tests: %v\n", err)
		os.Exit(1)
	}
	manifest := testfw.TestManifestID(tests)

	if *iface == "" {
		*iface = cfg.MachineA.Iface
	}
	if *serverIP == "" {
		*serverIP = cfg.MachineB.IP4
	}
	if *serverIP6 == "" {
		*serverIP6 = cfg.MachineB.IP6
	}
	if *sleepMs == 0 {
		*sleepMs = cfg.Test.SleepMs
	}
	if *verifyTimeoutSec == 0 {
		*verifyTimeoutSec = cfg.Test.VerifyTimeout
	}
	verifyPolicy := cfg.Test.VerifyPolicy
	if *verifyPolicyFlag != "" {
		verifyPolicy = *verifyPolicyFlag
	}
	verifyPolicy, err = testfw.NormalizeVerifyPolicy(verifyPolicy)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config: %v\n", err)
		os.Exit(2)
	}

	if *iface == "" || *serverIP == "" {
		fmt.Fprintln(os.Stderr, "error: -i and --server-ip are required (or set in config.ini)")
		os.Exit(2)
	}

	if !*keepOffloads {
		testfw.DisableOffloads(*iface)
		fmt.Println()
	}

	fmt.Printf("[suite]  loaded %d tests from %s\n", len(tests), *testsPath)
	fmt.Println()

	fmt.Println("[verify] loading all client-side programs ...")
	progs := make([]testfw.ProgSpec, 0)
	for _, t := range tests {
		if t.ClientProg != "" {
			progs = append(progs, testfw.ProgSpec{File: t.ClientProg, Type: t.ClientType})
		}
	}
	verifyTimeout := time.Duration(float64(time.Second) * *verifyTimeoutSec)
	if *verifyTimeoutSec < 0 {
		verifyTimeout = 0
	}
	failures := testfw.VerifyLoadWithTimeout(*progDir, *iface, progs, verifyTimeout)
	clientBlocked := testfw.BlockedTestsByFailures(tests, failures, "client")
	if len(failures) > 0 {
		for _, f := range failures {
			fmt.Fprintf(os.Stderr, "[verify] FAIL  %s: %s\n", f.File, f.Err)
		}
		if verifyPolicy == testfw.VerifyPolicyFail {
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "[verify] continuing: %d test(s) will be marked UNVERIFIED\n", len(clientBlocked))
	} else {
		fmt.Println("[verify] all OK")
	}
	fmt.Println()

	// RESULT: we listen, server connects.
	resultAddr := fmt.Sprintf(":%d", *resultPort)
	resultSrv, err := net.Listen("tcp4", resultAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "listen result %s: %v\n", resultAddr, err)
		os.Exit(1)
	}
	fmt.Printf("[result] listening on %s ...\n", resultAddr)

	// CTRL: we connect to server.  The server finishes its own verify phase
	// before it starts listening here, so by the time we are connected any
	// transient XDP programs attached during verify have already been removed.
	ctrlAddr := fmt.Sprintf("%s:%d", *serverIP, *ctrlPort)
	fmt.Printf("[ctrl]   connecting to %s ...\n", ctrlAddr)
	var ctrlConn net.Conn
	deadline := time.Now().Add(3 * time.Minute)
	for {
		ctrlConn, err = net.DialTimeout("tcp4", ctrlAddr, 2*time.Second)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			fmt.Fprintln(os.Stderr, "ERROR: server not reachable after 3 min — is it running?")
			os.Exit(1)
		}
		time.Sleep(200 * time.Millisecond)
	}
	ctrlIn := bufio.NewReader(ctrlConn)
	ctrlOut := bufio.NewWriter(ctrlConn)
	fmt.Println("[ctrl]   connected")

	ip6ok := checkConnectivity(*serverIP, *serverIP6)
	if !ip6ok {
		*serverIP6 = ""
	}

	ctrlOut.WriteString(testfw.FormatHello(manifest, ip6ok))
	ctrlOut.Flush()
	helloReply, err := ctrlIn.ReadString('\n')
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: server HELLO-OK failed: %v\n", err)
		os.Exit(1)
	}
	if strings.HasPrefix(strings.TrimSpace(helloReply), "ABORT:") {
		fmt.Fprintf(os.Stderr, "ERROR: server aborted: %s\n", strings.TrimPrefix(strings.TrimSpace(helloReply), "ABORT:"))
		os.Exit(1)
	}
	commonIPv6, err := testfw.ParseHelloOK(helloReply)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		os.Exit(1)
	}
	if !commonIPv6 {
		fmt.Println("[ctrl]   IPv6 tests will be skipped")
	}
	ctrlOut.WriteString(testfw.FormatVerifyBlocked(clientBlocked))
	ctrlOut.Flush()
	serverVerify, err := ctrlIn.ReadString('\n')
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: server VERIFY failed: %v\n", err)
		os.Exit(1)
	}
	if strings.HasPrefix(strings.TrimSpace(serverVerify), "ABORT:") {
		fmt.Fprintf(os.Stderr, "ERROR: server aborted: %s\n", strings.TrimPrefix(strings.TrimSpace(serverVerify), "ABORT:"))
		os.Exit(1)
	}
	serverBlocked, err := testfw.ParseVerifyBlocked(serverVerify)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		os.Exit(1)
	}
	blockedTests := testfw.MergeBlockedTests(serverBlocked, clientBlocked)

	// Accept result connection from server.
	resultSrv.(*net.TCPListener).SetDeadline(time.Now().Add(30 * time.Second))
	resultConn, err := resultSrv.Accept()
	if err != nil {
		fmt.Fprintln(os.Stderr, "ERROR: server did not connect to result port after 30 s")
		os.Exit(1)
	}
	resultSrv.Close()
	resultIn := bufio.NewReader(resultConn)
	fmt.Println("[result] server connected")
	fmt.Println()

	type result struct {
		name   string
		status string
	}
	var results []result

	for _, test := range tests {
		// Wait for server READY/SKIP signal.
		line, err := ctrlIn.ReadString('\n')
		if err != nil {
			fmt.Fprintf(os.Stderr, "ctrl read: %v\n", err)
			break
		}
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "ABORT:") {
			fmt.Fprintf(os.Stderr, "server aborted: %s\n", strings.TrimPrefix(line, "ABORT:"))
			break
		}
		if unverName, reason, ok := testfw.ParseNamedControl(line, "UNVERIFIED:"); ok {
			if unverName != test.Name {
				fmt.Fprintf(os.Stderr, "unverified name mismatch: got %q expected %q\n", unverName, test.Name)
				break
			}
			if knownReason, ok := blockedTests[test.Name]; ok && knownReason != reason {
				fmt.Fprintf(os.Stderr, "unverified reason mismatch for %s: got %q expected %q\n",
					test.Name, reason, knownReason)
				break
			}
			fmt.Printf("[unverified] %s  (%s)\n", test.Name, reason)
			results = append(results, result{test.Name, testfw.StatusUnverified})
			continue
		}
		if skipName, reason, ok := testfw.ParseNamedControl(line, "SKIP:"); ok {
			if skipName != test.Name {
				fmt.Fprintf(os.Stderr, "skip name mismatch: got %q expected %q\n", skipName, test.Name)
				break
			}
			fmt.Printf("[skip]   %s  (%s)\n", test.Name, reason)
			results = append(results, result{test.Name, testfw.StatusSkip})
			continue
		}
		readyName, _, ok := testfw.ParseNamedControl(line, "READY:")
		if !ok {
			fmt.Fprintf(os.Stderr, "unexpected ctrl message: %q\n", line)
			break
		}
		if readyName != test.Name {
			fmt.Fprintf(os.Stderr, "ready name mismatch: got %q expected %q\n", readyName, test.Name)
			break
		}

		fmt.Printf("[test]   %s\n", test.Name)

		dstHost := *serverIP
		if test.Family == 6 {
			dstHost = *serverIP6
		}

		var h *testfw.ProgHandle
		if test.ClientProg != "" {
			h, err = testfw.LoadProg(*progDir, *iface, test.ClientProg, test.ClientType, *sleepMs)
			if err != nil {
				fmt.Fprintf(os.Stderr, "         ERROR: %v\n", err)
			}
			setActive(h)
		}

		sendPacket(dstHost, test.Proto, testfw.PortFrom, test.Family, test.PaddedPayload,
			*iface, cfg.MachineA.IP4, cfg.MachineA.IP6)
		fmt.Printf("         sent %s/IPv%d → %s:%d\n",
			strings.ToUpper(test.Proto), test.Family, dstHost, testfw.PortFrom)

		clearActive()
		testfw.UnloadProg(h)

		// Read result from server.
		rline, err := resultIn.ReadString('\n')
		if err != nil {
			fmt.Fprintf(os.Stderr, "result read: %v\n", err)
			results = append(results, result{test.Name, "?"})
			continue
		}
		rline = strings.TrimSpace(rline)
		if resultName, status, ok := testfw.ParseResult(rline); ok {
			if resultName != test.Name {
				fmt.Fprintf(os.Stderr, "result name mismatch: got %q expected %q\n", resultName, test.Name)
				results = append(results, result{test.Name, "?"})
				break
			}
			mark := "[ OK ]"
			if status != testfw.StatusOK {
				mark = "[FAIL]"
			}
			fmt.Printf("         %s\n", mark)
			results = append(results, result{test.Name, status})
		} else {
			fmt.Printf("         ? unexpected: %q\n", rline)
			results = append(results, result{test.Name, "?"})
		}
	}

	passed := 0
	skipped := 0
	unverified := 0
	executed := 0
	for _, r := range results {
		switch r.status {
		case testfw.StatusOK:
			passed++
			executed++
		case testfw.StatusSkip:
			skipped++
		case testfw.StatusUnverified:
			unverified++
		default:
			executed++
		}
	}
	sep := strings.Repeat("=", 44)
	fmt.Printf("\n%s\n  %d/%d passed, %d skipped, %d unverified\n%s\n",
		sep, passed, executed, skipped, unverified, sep)
	for _, r := range results {
		mark := "[ OK ]"
		if r.status == testfw.StatusSkip {
			mark = "[SKIP]"
		} else if r.status == testfw.StatusUnverified {
			mark = "[UNVERIFIED]"
		} else if r.status != testfw.StatusOK {
			mark = "[FAIL]"
		}
		fmt.Printf("  %s  %s\n", mark, r.name)
	}

	ctrlConn.Close()
	resultConn.Close()
}

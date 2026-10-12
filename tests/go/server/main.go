package main

import (
	"bufio"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	testfw "bonettests"
)

// activeHandle holds the program currently under test so the signal handler
// can unload it before the process exits.
var (
	activeMu     sync.Mutex
	activeHandle *testfw.ProgHandle
	activeEgress *testfw.ProgHandle
)

func setActive(h, he *testfw.ProgHandle) {
	activeMu.Lock()
	activeHandle = h
	activeEgress = he
	activeMu.Unlock()
}

func clearActive() {
	activeMu.Lock()
	activeHandle = nil
	activeEgress = nil
	activeMu.Unlock()
}

func installSignalHandler() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-ch
		fmt.Fprintln(os.Stderr, "\n[signal] interrupted — detaching BPF program")
		activeMu.Lock()
		h, he := activeHandle, activeEgress
		activeHandle = nil
		activeEgress = nil
		activeMu.Unlock()
		testfw.UnloadProg(h)
		testfw.UnloadProg(he)
		os.Exit(130)
	}()
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == testfw.VerifyLoadSubcommand {
		os.Exit(testfw.RunVerifyLoadSubcommand(os.Args[2:]))
	}

	var cfgPaths testfw.ConfigPaths
	flag.Var(&cfgPaths, "config", "path to config.ini (can be repeated; later files override earlier)")
	testsPath := flag.String("tests", "tests.csv", "path to suite test cases CSV")
	iface := flag.String("i", "", "network interface (Machine B)")
	clientIP := flag.String("client-ip", "", "IPv4 address of Machine A")
	clientIP6 := flag.String("client-ip6", "", "IPv6 address of Machine A (skip IPv6 tests if absent)")
	ctrlPort := flag.Int("ctrl-port", testfw.CtrlPort, "control port (we listen)")
	resultPort := flag.Int("result-port", testfw.ResultPort, "result port (we connect to client)")
	progDir := flag.String("prog-dir", ".", "directory containing .o files")
	sleepMs := flag.Int("sleep", 0, "post-attach sleep in ms (0 = use config)")
	timeoutSec := flag.Float64("timeout", 0, "per-test packet wait in seconds (0 = use config)")
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
		*iface = cfg.MachineB.Iface
	}
	if *clientIP == "" {
		*clientIP = cfg.MachineA.IP4
	}
	if *clientIP6 == "" {
		*clientIP6 = cfg.MachineA.IP6
	}
	if *sleepMs == 0 {
		*sleepMs = cfg.Test.SleepMs
	}
	if *timeoutSec == 0 {
		*timeoutSec = cfg.Test.Timeout
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

	if *iface == "" || *clientIP == "" {
		fmt.Fprintln(os.Stderr, "error: -i and --client-ip are required (or set in config.ini)")
		os.Exit(2)
	}

	if !*keepOffloads {
		testfw.DisableOffloads(*iface)
		fmt.Println()
	}

	testfw.AddLoRoute("198.51.100.0/24")
	defer testfw.DelLoRoute("198.51.100.0/24")

	fmt.Printf("[suite]  loaded %d tests from %s\n", len(tests), *testsPath)
	fmt.Println()

	fmt.Println("[verify] loading all server-side programs ...")
	progs := make([]testfw.ProgSpec, 0, len(tests)*2)
	for _, t := range tests {
		progs = append(progs, testfw.ProgSpec{File: t.ServerProg, Type: t.ServerType})
		if t.ServerEgressProg != "" {
			progs = append(progs, testfw.ProgSpec{File: t.ServerEgressProg, Type: t.ServerEgressType})
		}
	}
	verifyTimeout := time.Duration(float64(time.Second) * *verifyTimeoutSec)
	if *verifyTimeoutSec < 0 {
		verifyTimeout = 0
	}
	failures := testfw.VerifyLoadWithTimeout(*progDir, *iface, progs, verifyTimeout)
	serverBlocked := testfw.BlockedTestsByFailures(tests, failures, "server")
	if len(failures) > 0 {
		for _, f := range failures {
			fmt.Fprintf(os.Stderr, "[verify] FAIL  %s: %s\n", f.File, f.Err)
		}
		if verifyPolicy == testfw.VerifyPolicyFail {
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "[verify] continuing: %d test(s) will be marked UNVERIFIED\n", len(serverBlocked))
	} else {
		fmt.Println("[verify] all OK")
	}
	fmt.Println()

	// CTRL: we listen, client connects and we send READY.
	ctrlAddr := fmt.Sprintf(":%d", *ctrlPort)
	ctrlSrv, err := net.Listen("tcp4", ctrlAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "listen ctrl %s: %v\n", ctrlAddr, err)
		os.Exit(1)
	}
	fmt.Printf("[ctrl]   waiting on %s ...\n", ctrlAddr)
	ctrlSrv.(*net.TCPListener).SetDeadline(time.Now().Add(3 * time.Minute))
	ctrlConn, err := ctrlSrv.Accept()
	if err != nil {
		fmt.Fprintln(os.Stderr, "ERROR: no client connected after 3 min — is it running?")
		os.Exit(1)
	}
	ctrlSrv.Close()
	ctrlIn := bufio.NewReader(ctrlConn)
	ctrlOut := bufio.NewWriter(ctrlConn)
	fmt.Printf("[ctrl]   %s connected\n", ctrlConn.RemoteAddr())

	hello, err := ctrlIn.ReadString('\n')
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: client HELLO failed: %v\n", err)
		os.Exit(1)
	}
	clientManifest, clientIPv6OK, err := testfw.ParseHello(hello)
	if err != nil {
		ctrlOut.WriteString(testfw.FormatAbort(err.Error()))
		ctrlOut.Flush()
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		os.Exit(1)
	}
	if clientManifest != manifest {
		msg := fmt.Sprintf("suite manifest mismatch: server=%s client=%s", manifest, clientManifest)
		ctrlOut.WriteString(testfw.FormatAbort(msg))
		ctrlOut.Flush()
		fmt.Fprintf(os.Stderr, "ERROR: %s\n", msg)
		os.Exit(1)
	}
	commonIPv6 := *clientIP6 != "" && clientIPv6OK
	ctrlOut.WriteString(testfw.FormatHelloOK(commonIPv6))
	ctrlOut.Flush()

	clientVerify, err := ctrlIn.ReadString('\n')
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: client VERIFY failed: %v\n", err)
		os.Exit(1)
	}
	clientBlocked, err := testfw.ParseVerifyBlocked(clientVerify)
	if err != nil {
		ctrlOut.WriteString(testfw.FormatAbort(err.Error()))
		ctrlOut.Flush()
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		os.Exit(1)
	}
	ctrlOut.WriteString(testfw.FormatVerifyBlocked(serverBlocked))
	ctrlOut.Flush()
	blockedTests := testfw.MergeBlockedTests(serverBlocked, clientBlocked)

	// RESULT: we connect to client's result port.
	resultAddr := fmt.Sprintf("%s:%d", *clientIP, *resultPort)
	fmt.Printf("[result] connecting to %s ...\n", resultAddr)
	var resultConn net.Conn
	deadline := time.Now().Add(30 * time.Second)
	for {
		resultConn, err = net.DialTimeout("tcp4", resultAddr, 2*time.Second)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			fmt.Fprintln(os.Stderr, "ERROR: client result port not reachable after 30 s")
			os.Exit(1)
		}
		time.Sleep(200 * time.Millisecond)
	}
	resultOut := bufio.NewWriter(resultConn)
	fmt.Println("[result] connected")
	fmt.Println()

	timeout := time.Duration(float64(time.Second) * *timeoutSec)
	type result struct {
		name   string
		status string
	}
	var results []result

	for _, test := range tests {
		if reason, blocked := blockedTests[test.Name]; blocked {
			fmt.Printf("[unverified] %s  (%s)\n", test.Name, reason)
			ctrlOut.WriteString(testfw.FormatUnverified(test.Name, reason))
			ctrlOut.Flush()
			results = append(results, result{test.Name, testfw.StatusUnverified})
			continue
		}

		if test.Family == 6 && !commonIPv6 {
			reason := "ipv6_unavailable"
			if *clientIP6 == "" {
				reason = "client_ip6_not_set"
			} else if !clientIPv6OK {
				reason = "client_ipv6_unreachable"
			}
			fmt.Printf("[skip]   %s  (%s)\n", test.Name, reason)
			ctrlOut.WriteString(testfw.FormatSkip(test.Name, reason))
			ctrlOut.Flush()
			results = append(results, result{test.Name, testfw.StatusSkip})
			continue
		}

		fmt.Printf("[test]   %s\n", test.Name)
		ok := false

		if test.ServerEgressProg != "" {
			// TCP handshake test: listener must be up before BPF is attached.
			// Start listener goroutine first and wait for it to be ready.
			arrived := make(chan bool, 1)
			listenerReady := make(chan struct{})

			go func(t testfw.Test) {
				network := "tcp4"
				if t.Family == 6 {
					network = "tcp6"
				}
				ln, lnErr := net.Listen(network, fmt.Sprintf(":%d", testfw.PortTo))
				if lnErr != nil {
					fmt.Printf("[warn]   WaitForTCPConn listen: %v\n", lnErr)
					close(listenerReady)
					arrived <- false
					return
				}
				defer ln.Close()
				close(listenerReady)
				ln.(*net.TCPListener).SetDeadline(time.Now().Add(timeout))
				conn, connErr := ln.Accept()
				if connErr == nil {
					conn.Close()
				}
				arrived <- (connErr == nil)
			}(test)

			<-listenerReady

			var loadErr, egressErr error
			h, loadErr := testfw.LoadProg(*progDir, *iface, test.ServerProg, test.ServerType, *sleepMs)
			if loadErr != nil {
				fmt.Fprintf(os.Stderr, "         ERROR (ingress): %v\n", loadErr)
			}
			he, egressErr := testfw.LoadProg(*progDir, *iface, test.ServerEgressProg, test.ServerEgressType, 0)
			if egressErr != nil {
				fmt.Fprintf(os.Stderr, "         ERROR (egress): %v\n", egressErr)
			}
			setActive(h, he)

			ctrlOut.WriteString(testfw.FormatReady(test.Name))
			ctrlOut.Flush()

			select {
			case ok = <-arrived:
			case <-time.After(timeout + 2*time.Second):
			}

			clearActive()
			testfw.UnloadProg(h)
			testfw.UnloadProg(he)

			status := testfw.StatusFail
			if ok && loadErr == nil && egressErr == nil {
				status = testfw.StatusOK
			}
			results = append(results, result{test.Name, status})
			if status == testfw.StatusOK {
				fmt.Println("         [ OK ]")
			} else {
				fmt.Println("         [FAIL]")
			}
			resultOut.WriteString(testfw.FormatResult(test.Name, status))
			resultOut.Flush()

		} else {
			// Default: optional packet observation plus optional BPF map result.
			h, loadErr := testfw.LoadProg(*progDir, *iface, test.ServerProg, test.ServerType, *sleepMs)
			if loadErr != nil {
				fmt.Fprintf(os.Stderr, "         ERROR: %v\n", loadErr)
			}
			setActive(h, nil)

			wantPacket := test.WantsPacketResult()
			wantDrop := test.WantsDropResult()
			wantMap := test.WantsMapResult()

			var packetWaiter *testfw.PacketWaiter
			packetWaiterOK := true
			if wantPacket || wantDrop {
				packetWaiter, err = testfw.StartPacketWaiter(test.Proto, test.Family, testfw.PortTo, timeout)
				if err != nil {
					packetWaiterOK = false
					fmt.Fprintf(os.Stderr, "         packet waiter error: %v\n", err)
				}
			}

			ctrlOut.WriteString(testfw.FormatReady(test.Name))
			ctrlOut.Flush()

			packetOK := packetWaiterOK
			if wantPacket || wantDrop {
				arrivedOK := false
				if packetWaiterOK {
					arrivedOK = packetWaiter.Wait(timeout + 2*time.Second)
				}
				if wantPacket {
					packetOK = arrivedOK
				}
				if wantDrop {
					packetOK = !arrivedOK
				}
			}

			mapOK := true
			if wantMap {
				if loadErr != nil {
					mapOK = false
				} else {
					result, reported, err := testfw.WaitForTestResult(h, timeout)
					mapOK = err == nil && reported && result.OK()
					if err != nil {
						fmt.Fprintf(os.Stderr, "         map result error: %v\n", err)
					} else if !reported {
						fmt.Fprintln(os.Stderr, "         map result missing")
					} else if !result.OK() {
						fmt.Fprintf(os.Stderr, "         map result status=%d seen=0x%x expected=0x%x\n",
							result.Status, result.Seen, result.Expected)
						if result.Detail[0] != 0 {
							fmt.Fprintf(os.Stderr, "         detail: d[0]=%d d[1]=0x%x d[2]=0x%x\n",
								result.Detail[0], result.Detail[1], result.Detail[2])
						}
					}
				}
			}

			clearActive()
			testfw.UnloadProg(h)

			status := testfw.StatusFail
			if loadErr == nil && packetOK && mapOK {
				status = testfw.StatusOK
			}
			results = append(results, result{test.Name, status})
			if status == testfw.StatusOK {
				fmt.Println("         [ OK ]")
			} else {
				fmt.Println("         [FAIL]")
			}
			resultOut.WriteString(testfw.FormatResult(test.Name, status))
			resultOut.Flush()
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

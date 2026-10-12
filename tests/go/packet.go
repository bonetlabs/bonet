package testfw

import (
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
	"time"
)

// WaitForPacket waits up to timeout for a UDP or TCP packet arriving at port
// with the given address family (4 or 6). Used by the server to confirm the
// BPF program rewrote the destination port correctly.
func WaitForPacket(proto string, family, port int, timeout time.Duration) bool {
	waiter, err := StartPacketWaiter(proto, family, port, timeout)
	if err != nil {
		fmt.Printf("[warn] packet waiter: %v\n", err)
		return false
	}
	return waiter.Wait(timeout + time.Second)
}

// PacketWaiter receives packets after its socket/listener has already been
// created. This lets the server send READY only after observation is armed.
type PacketWaiter struct {
	done <-chan bool
}

func (w *PacketWaiter) Wait(max time.Duration) bool {
	if w == nil {
		return false
	}
	select {
	case ok := <-w.done:
		return ok
	case <-time.After(max):
		return false
	}
}

func StartPacketWaiter(proto string, family, port int, timeout time.Duration) (*PacketWaiter, error) {
	switch proto {
	case "udp":
		return startUDPWaiter(family, port, timeout)
	case "tcp":
		return startTCPRawWaiter(family, port, timeout)
	default:
		return nil, fmt.Errorf("unsupported packet proto %q", proto)
	}
}

func startUDPWaiter(family, port int, timeout time.Duration) (*PacketWaiter, error) {
	network, addr := "udp4", fmt.Sprintf(":%d", port)
	if family == 6 {
		network, addr = "udp6", fmt.Sprintf("[::]:%d", port)
	}
	conn, err := net.ListenPacket(network, addr)
	if err != nil {
		return nil, fmt.Errorf("waitUDP listen: %w", err)
	}
	conn.SetReadDeadline(time.Now().Add(timeout))
	done := make(chan bool, 1)
	go func() {
		defer conn.Close()
		buf := make([]byte, 256)
		_, _, err := conn.ReadFrom(buf)
		done <- err == nil
	}()
	return &PacketWaiter{done: done}, nil
}

// WaitForTCPConn opens a real TCP listener on port and waits for a connection.
// Because the kernel verifies checksums before delivering to a TCP socket, a
// connection that completes proves the checksum was correct end-to-end.
// The caller must ensure the listener is started before the BPF program is
// attached and the READY signal is sent.
func WaitForTCPConn(family, port int, timeout time.Duration) bool {
	network := "tcp4"
	if family == 6 {
		network = "tcp6"
	}
	ln, err := net.Listen(network, fmt.Sprintf(":%d", port))
	if err != nil {
		fmt.Printf("[warn] WaitForTCPConn listen: %v\n", err)
		return false
	}
	defer ln.Close()
	ln.(*net.TCPListener).SetDeadline(time.Now().Add(timeout))
	conn, err := ln.Accept()
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func startTCPRawWaiter(family, port int, timeout time.Duration) (*PacketWaiter, error) {
	af := syscall.AF_INET
	if family == 6 {
		af = syscall.AF_INET6
	}
	fd, err := syscall.Socket(af, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		return nil, fmt.Errorf("waitTCP socket: %w", err)
	}

	// Set receive timeout so Recvfrom unblocks when the deadline passes.
	tv := syscall.NsecToTimeval(timeout.Nanoseconds())
	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("waitTCP timeout: %w", err)
	}

	done := make(chan bool, 1)
	go func() {
		defer syscall.Close(fd)
		done <- receiveTCPRaw(fd, family, port, timeout)
	}()
	return &PacketWaiter{done: done}, nil
}

func receiveTCPRaw(fd, family, port int, timeout time.Duration) bool {
	buf := make([]byte, 65535)
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			return false
		}
		data := buf[:n]
		// For AF_INET raw TCP socket the packet starts with the IPv4 header.
		// For AF_INET6 raw TCP socket the kernel strips the IPv6 header.
		var tcp []byte
		if family == 4 {
			if len(data) < 1 {
				continue
			}
			ihl := int(data[0]&0xf) * 4
			if len(data) < ihl+4 {
				continue
			}
			tcp = data[ihl:]
		} else {
			tcp = data
		}
		if len(tcp) >= 4 && int(binary.BigEndian.Uint16(tcp[2:4])) == port {
			return true
		}
	}
	return false
}

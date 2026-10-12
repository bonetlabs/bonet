package testfw

import (
	"encoding/binary"
	"fmt"
	"net"
	"os/exec"
	"syscall"
)

const (
	ethPIP          = 0x0800
	ethPARP         = 0x0806
	ethP8021Q       = 0x8100
	ethPIPv6        = 0x86dd
	ethPMPLSUC      = 0x8847
	ipProtoUDP      = 17
	ipProtoIPIP     = 4
	ipProtoIPv6     = 41
	ipProtoIPv6Frag = 44
	ipProtoIPv6Opts = 60
	ipProtoICMPv6   = 58
	ipv6NextRouting = 43
)

var broadcastMAC = []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

func buildMPLSLSE(label uint32, tc uint8, bos bool, ttl uint8) []byte {
	lse := (label << 12) | (uint32(tc&0x7) << 9) | uint32(ttl)
	if bos {
		lse |= 1 << 8
	}
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, lse)
	return b
}

func buildUDPPayload(sport, dport int, payload []byte) []byte {
	udp := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(udp[0:2], uint16(sport))
	binary.BigEndian.PutUint16(udp[2:4], uint16(dport))
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
	copy(udp[8:], payload)
	return udp
}

func buildIPv4Packet(srcIP, dstIP string, proto byte, payload []byte) []byte {
	src := net.ParseIP(srcIP).To4()
	dst := net.ParseIP(dstIP).To4()
	if src == nil || dst == nil {
		return nil
	}
	totalLen := 20 + len(payload)
	pkt := make([]byte, totalLen)
	ip := pkt[:20]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(ip[4:6], 0x1234)
	ip[8] = 64
	ip[9] = proto
	copy(ip[12:16], src)
	copy(ip[16:20], dst)
	binary.BigEndian.PutUint16(ip[10:12], ipv4Checksum(ip))
	copy(pkt[20:], payload)
	return pkt
}

func buildIPv6Packet(srcIP6, dstIP6 string, nexthdr byte, payload []byte) []byte {
	src := net.ParseIP(srcIP6).To16()
	dst := net.ParseIP(dstIP6).To16()
	if src == nil || dst == nil {
		return nil
	}
	pkt := make([]byte, 40+len(payload))
	ip6 := pkt[:40]
	ip6[0] = 0x60
	binary.BigEndian.PutUint16(ip6[4:6], uint16(len(payload)))
	ip6[6] = nexthdr
	ip6[7] = 64
	copy(ip6[8:24], src)
	copy(ip6[24:40], dst)
	copy(pkt[40:], payload)
	return pkt
}

// SendMPLSUDP4 sends an Ethernet frame carrying 1 or 2 MPLS labels over IPv4/UDP.
// numLabels must be 1 or 2. Port is both sport and dport.
func SendMPLSUDP4(ifaceName, srcIP, dstIP string, numLabels, port int) error {
	if numLabels != 1 && numLabels != 2 {
		return fmt.Errorf("invalid numLabels %d", numLabels)
	}
	iface, srcMAC, err := rawInterface(ifaceName)
	if err != nil {
		return err
	}
	udp := buildUDPPayload(port, port, []byte("BNTMPLS"))
	ip := buildIPv4Packet(srcIP, dstIP, ipProtoUDP, udp)
	if ip == nil {
		return fmt.Errorf("invalid IPv4 address: src=%q dst=%q", srcIP, dstIP)
	}

	var mplsHdr []byte
	if numLabels == 1 {
		// label=100, tc=0, BOS=true, ttl=64
		mplsHdr = buildMPLSLSE(100, 0, true, 64)
	} else {
		// outer: label=200, BOS=false; inner: label=100, BOS=true
		outer := buildMPLSLSE(200, 0, false, 64)
		inner := buildMPLSLSE(100, 0, true, 64)
		mplsHdr = append(outer, inner...)
	}

	payload := append(mplsHdr, ip...)
	hdrLen := 14
	frame := make([]byte, hdrLen+len(payload))
	copy(frame[0:6], broadcastMAC)
	copy(frame[6:12], srcMAC)
	binary.BigEndian.PutUint16(frame[12:14], ethPMPLSUC)
	copy(frame[14:], payload)
	return sendFrame(iface, ethPMPLSUC, frame, broadcastMAC)
}

// SendMPLSUDP6 sends an Ethernet frame carrying a single MPLS label over IPv6/UDP.
func SendMPLSUDP6(ifaceName, srcIP6, dstIP6 string, port int) error {
	iface, srcMAC, err := rawInterface(ifaceName)
	if err != nil {
		return err
	}
	udp := buildUDPPayload(port, port, []byte("BNTMPLS"))
	ip6 := buildIPv6Packet(srcIP6, dstIP6, ipProtoUDP, udp)
	if ip6 == nil {
		return fmt.Errorf("invalid IPv6 address: src=%q dst=%q", srcIP6, dstIP6)
	}
	// label=99, tc=0, BOS=true, ttl=64
	lse := buildMPLSLSE(99, 0, true, 64)
	payload := append(lse, ip6...)
	frame := make([]byte, 14+len(payload))
	copy(frame[0:6], broadcastMAC)
	copy(frame[6:12], srcMAC)
	binary.BigEndian.PutUint16(frame[12:14], ethPMPLSUC)
	copy(frame[14:], payload)
	return sendFrame(iface, ethPMPLSUC, frame, broadcastMAC)
}

// SendIPIPUDP4 sends IPv4-in-IPv4 (IPIP) carrying UDP.
// Outer src/dst are provided; inner uses fixed IPs 10.100.0.1→10.100.0.2.
func SendIPIPUDP4(ifaceName, srcIP, dstIP string, port int) error {
	iface, srcMAC, err := rawInterface(ifaceName)
	if err != nil {
		return err
	}
	udp := buildUDPPayload(port, port, []byte("BNTIPIP"))
	innerIP := buildIPv4Packet("10.100.0.1", "10.100.0.2", ipProtoUDP, udp)
	if innerIP == nil {
		return fmt.Errorf("buildIPv4Packet inner failed")
	}
	outerIP := buildIPv4Packet(srcIP, dstIP, ipProtoIPIP, innerIP)
	if outerIP == nil {
		return fmt.Errorf("invalid IPv4 address: src=%q dst=%q", srcIP, dstIP)
	}
	frame := makeEthernetFrame(srcMAC, broadcastMAC, ethPIP, outerIP)
	return sendFrame(iface, ethPIP, frame, broadcastMAC)
}

// SendIPv6inIPv4UDP sends IPv6-in-IPv4 (proto=41) carrying UDP.
// Outer IPv4 src/dst are provided; inner IPv6 uses fixed fd00::1→fd00::2.
func SendIPv6inIPv4UDP(ifaceName, srcIP4, dstIP4 string, port int) error {
	iface, srcMAC, err := rawInterface(ifaceName)
	if err != nil {
		return err
	}
	udp := buildUDPPayload(port, port, []byte("BNTV6V4"))
	innerIP6 := buildIPv6Packet("fd00::1", "fd00::2", ipProtoUDP, udp)
	if innerIP6 == nil {
		return fmt.Errorf("buildIPv6Packet inner failed")
	}
	outerIP := buildIPv4Packet(srcIP4, dstIP4, ipProtoIPv6, innerIP6)
	if outerIP == nil {
		return fmt.Errorf("invalid IPv4 address: src=%q dst=%q", srcIP4, dstIP4)
	}
	frame := makeEthernetFrame(srcMAC, broadcastMAC, ethPIP, outerIP)
	return sendFrame(iface, ethPIP, frame, broadcastMAC)
}

// SendIPv4inIPv6UDP sends IPv4-in-IPv6 (nexthdr=4) carrying UDP.
// Outer IPv6 src/dst are provided; inner IPv4 uses fixed 10.100.0.1→10.100.0.2.
func SendIPv4inIPv6UDP(ifaceName, srcIP6, dstIP6 string, port int) error {
	iface, srcMAC, err := rawInterface(ifaceName)
	if err != nil {
		return err
	}
	udp := buildUDPPayload(port, port, []byte("BNTV4V6"))
	innerIP := buildIPv4Packet("10.100.0.1", "10.100.0.2", ipProtoUDP, udp)
	if innerIP == nil {
		return fmt.Errorf("buildIPv4Packet inner failed")
	}
	outerIP6 := buildIPv6Packet(srcIP6, dstIP6, ipProtoIPIP, innerIP)
	if outerIP6 == nil {
		return fmt.Errorf("invalid IPv6 address: src=%q dst=%q", srcIP6, dstIP6)
	}
	frame := makeEthernetFrame(srcMAC, broadcastMAC, ethPIPv6, outerIP6)
	return sendFrame(iface, ethPIPv6, frame, broadcastMAC)
}

// SendSRv6EncapUDP4 sends an SRv6 H.Encaps packet wrapping inner IPv4/UDP.
// Outer IPv6 src/dst are provided; inner IPv4 uses fixed 10.100.0.1→10.100.0.2.
// The SRH carries one segment (dstIP6) with nexthdr=IPPROTO_IPIP (4).
func SendSRv6EncapUDP4(ifaceName, srcIP6, dstIP6 string, port int) error {
	iface, srcMAC, err := rawInterface(ifaceName)
	if err != nil {
		return err
	}
	outerSrc := net.ParseIP(srcIP6).To16()
	outerDst := net.ParseIP(dstIP6).To16()
	if outerSrc == nil || outerDst == nil {
		return fmt.Errorf("invalid IPv6 address: src=%q dst=%q", srcIP6, dstIP6)
	}

	udp := buildUDPPayload(port, port, []byte("BNTSRV6"))
	innerIP := buildIPv4Packet("10.100.0.1", "10.100.0.2", ipProtoUDP, udp)
	if innerIP == nil {
		return fmt.Errorf("buildIPv4Packet inner failed")
	}

	// SRH: nexthdr=4 (IPPROTO_IPIP), hdrlen=2 (8+2*8=24 bytes total),
	//      type=4, segments_left=0, first_segment=0, flags=0, tag=0,
	//      segment[0]=outerDst (16 bytes).
	srh := make([]byte, 24)
	srh[0] = ipProtoIPIP // nexthdr = inner IPv4
	srh[1] = 2           // hdrlen: (2+1)*8 = 24 bytes total
	srh[2] = 4           // type = SRv6
	srh[3] = 0           // segments_left
	srh[4] = 0           // first_segment
	// srh[5] = flags, srh[6:8] = tag = 0
	copy(srh[8:24], outerDst)

	payload := append(srh, innerIP...)
	// Outer IPv6: nexthdr=43 (NEXTHDR_ROUTING)
	outerIP6 := buildIPv6Packet(srcIP6, dstIP6, ipv6NextRouting, payload)
	if outerIP6 == nil {
		return fmt.Errorf("buildIPv6Packet outer failed")
	}
	frame := makeEthernetFrame(srcMAC, broadcastMAC, ethPIPv6, outerIP6)
	return sendFrame(iface, ethPIPv6, frame, broadcastMAC)
}

func SendICMPPing(host string, family int) {
	f := "-4"
	if family == 6 {
		f = "-6"
	}
	_ = exec.Command("ping", f, "-c", "1", "-W", "1", host).Run()
}

func SendARPRequest(ifaceName, senderIP, targetIP string) error {
	iface, srcMAC, err := rawInterface(ifaceName)
	if err != nil {
		return err
	}
	spa := net.ParseIP(senderIP).To4()
	tpa := net.ParseIP(targetIP).To4()
	if spa == nil || tpa == nil {
		return fmt.Errorf("invalid ARP IPv4 address: sender=%q target=%q", senderIP, targetIP)
	}

	frame := make([]byte, 14+28)
	copy(frame[0:6], broadcastMAC)
	copy(frame[6:12], srcMAC)
	binary.BigEndian.PutUint16(frame[12:14], ethPARP)
	arp := frame[14:]
	binary.BigEndian.PutUint16(arp[0:2], 1)
	binary.BigEndian.PutUint16(arp[2:4], ethPIP)
	arp[4] = 6
	arp[5] = 4
	binary.BigEndian.PutUint16(arp[6:8], 1)
	copy(arp[8:14], srcMAC)
	copy(arp[14:18], spa)
	copy(arp[18:24], make([]byte, 6))
	copy(arp[24:28], tpa)
	return sendFrame(iface, ethPARP, frame, broadcastMAC)
}

func SendVLANUDP4(ifaceName, srcIP, dstIP string, depth int, sport, dport int) error {
	if depth != 1 && depth != 2 {
		return fmt.Errorf("invalid VLAN depth %d", depth)
	}
	iface, srcMAC, err := rawInterface(ifaceName)
	if err != nil {
		return err
	}
	ip := buildIPv4UDP(srcIP, dstIP, 0, sport, dport, []byte("BNTVLAN"))
	if ip == nil {
		return fmt.Errorf("invalid IPv4 address: src=%q dst=%q", srcIP, dstIP)
	}

	hdrLen := 14 + depth*4
	frame := make([]byte, hdrLen+len(ip))
	copy(frame[0:6], broadcastMAC)
	copy(frame[6:12], srcMAC)
	binary.BigEndian.PutUint16(frame[12:14], ethP8021Q)
	off := 14
	if depth == 1 {
		binary.BigEndian.PutUint16(frame[off:off+2], 100)
		binary.BigEndian.PutUint16(frame[off+2:off+4], ethPIP)
		off += 4
	} else {
		binary.BigEndian.PutUint16(frame[off:off+2], 100)
		binary.BigEndian.PutUint16(frame[off+2:off+4], ethP8021Q)
		off += 4
		binary.BigEndian.PutUint16(frame[off:off+2], 200)
		binary.BigEndian.PutUint16(frame[off+2:off+4], ethPIP)
		off += 4
	}
	copy(frame[off:], ip)
	return sendFrame(iface, ethP8021Q, frame, broadcastMAC)
}

func SendIPv4UDPFragment(ifaceName, srcIP, dstIP string, sport, dport int) error {
	iface, srcMAC, err := rawInterface(ifaceName)
	if err != nil {
		return err
	}
	ip := buildIPv4UDP(srcIP, dstIP, 0x2000, sport, dport, []byte("BNTFRAG"))
	if ip == nil {
		return fmt.Errorf("invalid IPv4 address: src=%q dst=%q", srcIP, dstIP)
	}
	frame := makeEthernetFrame(srcMAC, broadcastMAC, ethPIP, ip)
	return sendFrame(iface, ethPIP, frame, broadcastMAC)
}

func SendIPv4UDPNonFirstFragment(ifaceName, srcIP, dstIP string) error {
	iface, srcMAC, err := rawInterface(ifaceName)
	if err != nil {
		return err
	}
	ip := buildIPv4RawFragment(srcIP, dstIP, 0x0001, ipProtoUDP, []byte("BNTFRAG"))
	if ip == nil {
		return fmt.Errorf("invalid IPv4 address: src=%q dst=%q", srcIP, dstIP)
	}
	frame := makeEthernetFrame(srcMAC, broadcastMAC, ethPIP, ip)
	return sendFrame(iface, ethPIP, frame, broadcastMAC)
}

func SendIPv6UDPFirstFragment(ifaceName, srcIP, dstIP string, sport, dport int) error {
	iface, srcMAC, err := rawInterface(ifaceName)
	if err != nil {
		return err
	}
	udpPayload := []byte("BNTFRAG")
	udp := make([]byte, 8+len(udpPayload))
	binary.BigEndian.PutUint16(udp[0:2], uint16(sport))
	binary.BigEndian.PutUint16(udp[2:4], uint16(dport))
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)+8))
	copy(udp[8:], udpPayload)

	ip6 := buildIPv6Fragment(srcIP, dstIP, ipProtoUDP, 0x0001, udp)
	if ip6 == nil {
		return fmt.Errorf("invalid IPv6 address: src=%q dst=%q", srcIP, dstIP)
	}
	frame := makeEthernetFrame(srcMAC, broadcastMAC, ethPIPv6, ip6)
	return sendFrame(iface, ethPIPv6, frame, broadcastMAC)
}

func SendIPv6UDPNonFirstFragment(ifaceName, srcIP, dstIP string) error {
	iface, srcMAC, err := rawInterface(ifaceName)
	if err != nil {
		return err
	}
	ip6 := buildIPv6Fragment(srcIP, dstIP, ipProtoUDP, 0x0008, []byte("BNTFRAG"))
	if ip6 == nil {
		return fmt.Errorf("invalid IPv6 address: src=%q dst=%q", srcIP, dstIP)
	}
	frame := makeEthernetFrame(srcMAC, broadcastMAC, ethPIPv6, ip6)
	return sendFrame(iface, ethPIPv6, frame, broadcastMAC)
}

func SendIPv6ExtICMP6(ifaceName, srcIP, dstIP string, tooDeep bool) error {
	iface, srcMAC, err := rawInterface(ifaceName)
	if err != nil {
		return err
	}
	src := net.ParseIP(srcIP).To16()
	dst := net.ParseIP(dstIP).To16()
	if src == nil || dst == nil {
		return fmt.Errorf("invalid IPv6 address: src=%q dst=%q", srcIP, dstIP)
	}

	extCount := 1
	if tooDeep {
		extCount = 7
	}
	payloadLen := extCount*8 + 8
	ip6 := make([]byte, 40+payloadLen)
	ip6[0] = 0x60
	binary.BigEndian.PutUint16(ip6[4:6], uint16(payloadLen))
	ip6[6] = ipProtoIPv6Opts
	ip6[7] = 64
	copy(ip6[8:24], src)
	copy(ip6[24:40], dst)
	off := 40
	for i := 0; i < extCount; i++ {
		next := byte(ipProtoICMPv6)
		if i+1 < extCount {
			next = ipProtoIPv6Opts
		}
		ip6[off] = next
		ip6[off+1] = 0
		off += 8
	}
	ip6[off] = 128 // echo request
	ip6[off+1] = 0
	binary.BigEndian.PutUint16(ip6[off+4:off+6], 0x1234)
	binary.BigEndian.PutUint16(ip6[off+6:off+8], 1)

	frame := makeEthernetFrame(srcMAC, broadcastMAC, ethPIPv6, ip6)
	return sendFrame(iface, ethPIPv6, frame, broadcastMAC)
}

func rawInterface(ifaceName string) (*net.Interface, []byte, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, nil, err
	}
	if len(iface.HardwareAddr) < 6 {
		return nil, nil, fmt.Errorf("interface %s has no Ethernet MAC address", ifaceName)
	}
	return iface, []byte(iface.HardwareAddr[:6]), nil
}

func makeEthernetFrame(srcMAC, dstMAC []byte, ethertype uint16, payload []byte) []byte {
	frame := make([]byte, 14+len(payload))
	copy(frame[0:6], dstMAC)
	copy(frame[6:12], srcMAC)
	binary.BigEndian.PutUint16(frame[12:14], ethertype)
	copy(frame[14:], payload)
	return frame
}

func buildIPv4UDP(srcIP, dstIP string, fragOff uint16, sport, dport int, payload []byte) []byte {
	src := net.ParseIP(srcIP).To4()
	dst := net.ParseIP(dstIP).To4()
	if src == nil || dst == nil {
		return nil
	}
	totalLen := 20 + 8 + len(payload)
	pkt := make([]byte, totalLen)
	ip := pkt[:20]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(ip[4:6], 0x1234)
	binary.BigEndian.PutUint16(ip[6:8], fragOff)
	ip[8] = 64
	ip[9] = ipProtoUDP
	copy(ip[12:16], src)
	copy(ip[16:20], dst)
	binary.BigEndian.PutUint16(ip[10:12], ipv4Checksum(ip))

	udp := pkt[20:28]
	binary.BigEndian.PutUint16(udp[0:2], uint16(sport))
	binary.BigEndian.PutUint16(udp[2:4], uint16(dport))
	binary.BigEndian.PutUint16(udp[4:6], uint16(8+len(payload)))
	copy(pkt[28:], payload)
	return pkt
}

func buildIPv4RawFragment(srcIP, dstIP string, fragOff uint16, proto byte, payload []byte) []byte {
	src := net.ParseIP(srcIP).To4()
	dst := net.ParseIP(dstIP).To4()
	if src == nil || dst == nil {
		return nil
	}
	totalLen := 20 + len(payload)
	pkt := make([]byte, totalLen)
	ip := pkt[:20]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(ip[4:6], 0x1234)
	binary.BigEndian.PutUint16(ip[6:8], fragOff)
	ip[8] = 64
	ip[9] = proto
	copy(ip[12:16], src)
	copy(ip[16:20], dst)
	binary.BigEndian.PutUint16(ip[10:12], ipv4Checksum(ip))
	copy(pkt[20:], payload)
	return pkt
}

func buildIPv6Fragment(srcIP, dstIP string, next byte, fragOffFlags uint16, payload []byte) []byte {
	src := net.ParseIP(srcIP).To16()
	dst := net.ParseIP(dstIP).To16()
	if src == nil || dst == nil {
		return nil
	}
	payloadLen := 8 + len(payload)
	pkt := make([]byte, 40+payloadLen)
	ip6 := pkt[:40]
	ip6[0] = 0x60
	binary.BigEndian.PutUint16(ip6[4:6], uint16(payloadLen))
	ip6[6] = ipProtoIPv6Frag
	ip6[7] = 64
	copy(ip6[8:24], src)
	copy(ip6[24:40], dst)

	frag := pkt[40:48]
	frag[0] = next
	binary.BigEndian.PutUint16(frag[2:4], fragOffFlags)
	binary.BigEndian.PutUint32(frag[4:8], 0x12345678)
	copy(pkt[48:], payload)
	return pkt
}

func ipv4Checksum(h []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(h); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(h[i : i+2]))
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func sendFrame(iface *net.Interface, ethertype uint16, frame, dstMAC []byte) error {
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(ethertype)))
	if err != nil {
		return err
	}
	defer syscall.Close(fd)

	var addr syscall.SockaddrLinklayer
	addr.Protocol = htons(ethertype)
	addr.Ifindex = iface.Index
	addr.Halen = 6
	copy(addr.Addr[:], dstMAC)
	return syscall.Sendto(fd, frame, 0, &addr)
}

func htons(v uint16) uint16 {
	return (v<<8)&0xff00 | v>>8
}

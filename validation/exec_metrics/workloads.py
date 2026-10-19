"""Packets for the XDP workloads of validation/framework (and baseline).

Each case is (workload, label, packet, maps, expected XDP action). maps holds the
initial map contents as {map: {key bytes: value bytes}}. The forwarding cases
need bpf_fib_lookup to succeed: FIB below is the route the VM is set up with
(vm_net.sh), and the interpreter returns the same result.
"""
import struct

XDP_ABORTED, XDP_DROP, XDP_PASS, XDP_TX, XDP_REDIRECT = range(5)

DST_MAC = bytes.fromhex('020000000001')
SRC_MAC = bytes.fromhex('020000000010')
# vm_net.sh: veth v0 (smac) with a permanent neighbour (dmac) as next hop
FIB = dict(smac=list(bytes.fromhex('020000000101')), dmac=list(bytes.fromhex('020000000202')),
           routes=[(2, bytes([48, 0, 0, 0]), 8), (2, bytes([10, 7, 0, 0]), 16),
                   (10, bytes.fromhex('fd03' + '00' * 14), 16), (10, bytes.fromhex('fd07' + '00' * 14), 16)])


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack(f'!{len(b) // 2}H', b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


def ip4(a):
    return bytes(int(x) for x in a.split('.'))


def ip6(a):
    import ipaddress
    return ipaddress.IPv6Address(a).packed


def eth(etype, payload):
    return DST_MAC + SRC_MAC + struct.pack('!H', etype) + payload


def ipv4(src, dst, proto, l4, ttl=64, tos=0):
    h = struct.pack('!BBHHHBBH4s4s', 0x45, tos, 20 + len(l4), 0x1234, 0x4000, ttl, proto, 0, ip4(src), ip4(dst))
    h = h[:10] + struct.pack('!H', csum(h)) + h[12:]
    return eth(0x0800, h + l4)


def ipv6(src, dst, nh, l4, hop=64):
    return eth(0x86dd, struct.pack('!IHBB16s16s', 0x60000000, len(l4), nh, hop, ip6(src), ip6(dst)) + l4)


def l4_csum(pseudo, seg, at):
    c = csum(pseudo + seg)
    return seg[:at] + struct.pack('!H', c) + seg[at + 2:]


def udp4(src, dst, sport, dport, payload=b'BONet workload!! ' * 2):
    seg = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    seg = l4_csum(ip4(src) + ip4(dst) + struct.pack('!BBH', 0, 17, len(seg)), seg, 6)
    return ipv4(src, dst, 17, seg)


def tcp4(src, dst, sport, dport, flags=0x02):
    seg = struct.pack('!HHIIBBHHH', sport, dport, 1000, 0, 0x50, flags, 64240, 0, 0)
    seg = l4_csum(ip4(src) + ip4(dst) + struct.pack('!BBH', 0, 6, len(seg)), seg, 16)
    return ipv4(src, dst, 6, seg)


def udp6(src, dst, sport, dport, payload=b'BONet workload!! ' * 2):
    seg = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    seg = l4_csum(ip6(src) + ip6(dst) + struct.pack('!IxxxB', len(seg), 17), seg, 6)
    return ipv6(src, dst, 17, seg)


def icmp6(src, dst, typ):
    seg = struct.pack('!BBHHH', typ, 0, 0, 0x42, 1) + b'ping'
    seg = l4_csum(ip6(src) + ip6(dst) + struct.pack('!IxxxB', len(seg), 58), seg, 2)
    return ipv6(src, dst, 58, seg)


def arp_request(spa, tpa):
    body = struct.pack('!HHBBH6s4s6s4s', 1, 0x0800, 6, 4, 1, SRC_MAC, ip4(spa), b'\0' * 6, ip4(tpa))
    return b'\xff' * 6 + SRC_MAC + struct.pack('!H', 0x0806) + body


def acl_key(proto, dport):     # struct acl_key {u8 l4_proto; u8 pad0; u16 dport;}, dport in host order
    return struct.pack('<BBH', proto, 0, dport)


def acl_value(action):         # struct acl_value {u8 action; u8 pad[7]; u64 packets; u64 bytes;}
    return struct.pack('<B7xQQ', action, 0, 0)


V4 = udp4('10.8.0.1', '48.0.0.2', 1234, 5678)
V4_OTHER = udp4('10.8.0.9', '10.6.0.1', 1234, 5678)
V6 = udp6('fd08::1', 'fd03::2', 1234, 5678)
V6_OTHER = udp6('fd08::9', 'fd06::1', 1234, 5678)
ACL = {'acl_rules': {acl_key(6, 22): acl_value(1), acl_key(17, 53): acl_value(0)}}

CASES = [
    ('xdp_acl_firewall_e2e', 'tcp4_drop', tcp4('10.8.0.1', '48.0.0.2', 40000, 22), ACL, XDP_DROP),
    ('xdp_acl_firewall_e2e', 'udp6_pass', udp6('fd08::1', 'fd03::2', 40000, 53), ACL, XDP_PASS),
    ('xdp_acl_firewall_e2e', 'no_rule', tcp4('10.8.0.1', '48.0.0.2', 40000, 80), ACL, XDP_PASS),
    ('xdp_arp_responder', 'request', arp_request('10.0.0.1', '10.0.0.2'), {}, XDP_TX),
    ('xdp_arp_responder', 'other_ip', arp_request('10.0.0.1', '10.0.0.3'), {}, XDP_PASS),
    ('xdp_fib4_forward', 'forward', V4, {}, XDP_REDIRECT),
    ('xdp_fib6_forward', 'forward', V6, {}, XDP_REDIRECT),
    ('xdp_firewall_map', 'syn_blocked', tcp4('10.8.0.1', '48.0.0.2', 40000, 23),
     {'blocked_tcp_ports': {struct.pack('<H', 23): b'\x01'}}, XDP_DROP),
    ('xdp_firewall_map', 'syn_open', tcp4('10.8.0.1', '48.0.0.2', 40000, 80),
     {'blocked_tcp_ports': {struct.pack('<H', 23): b'\x01'}}, XDP_PASS),
    ('xdp_firewall_static', 'syn_23', tcp4('10.8.0.1', '48.0.0.2', 40000, 23), {}, XDP_DROP),
    ('xdp_firewall_static', 'syn_80', tcp4('10.8.0.1', '48.0.0.2', 40000, 80), {}, XDP_PASS),
    ('xdp_ip6ip6_encap', 'encap', V6, {}, XDP_REDIRECT),
    ('xdp_ipip_encap', 'encap', V4, {}, XDP_REDIRECT),
    ('xdp_ipv6_icmp6_filter', 'echo_request', icmp6('fd08::1', 'fd03::2', 128), {}, XDP_DROP),
    ('xdp_ipv6_icmp6_filter', 'echo_reply', icmp6('fd08::1', 'fd03::2', 129), {}, XDP_PASS),
    ('xdp_mmlf', 'marked', V4, {}, XDP_REDIRECT),
    ('xdp_mmlf', 'unmarked', udp4('10.8.0.9', '48.0.0.2', 1234, 5678), {}, XDP_REDIRECT),
    ('xdp_mmlf6', 'marked', V6, {}, XDP_REDIRECT),
    ('xdp_mmlf6', 'unmarked', udp6('fd08::9', 'fd03::2', 1234, 5678), {}, XDP_REDIRECT),
    ('xdp_srv6_encap', 'encap6', V6, {}, XDP_REDIRECT),
    ('xdp_srv6_encap', 'encap4', V4, {}, XDP_REDIRECT),
    ('xdp_static_dnat', 'translate', V4, {}, XDP_REDIRECT),
    ('xdp_static_dnat', 'other_dst', V4_OTHER, {}, XDP_PASS),
    ('xdp_static_dnat6', 'translate', V6, {}, XDP_REDIRECT),
    ('xdp_static_dnat6', 'other_dst', V6_OTHER, {}, XDP_PASS),
]

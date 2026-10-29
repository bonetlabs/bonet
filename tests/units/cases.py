"""Packets and calls exercising every XDP global.

CASES: list of (global, label, packet, args, out prefill). OUT is the start of a
256-byte scratch buffer; pointer arguments point into it, and the prefill sets
its initial content (inputs such as addresses, or 0xff to check zeroing).

COMPARE: globals whose output depends on the machine rather than on BONet.
  'no_out'  the buffer holds the kernel's FIB result, which depends on the
            routing table: compare only the return value and the packet.
  'csum32'  the buffer holds the raw bpf_csum_diff value, whose 32-bit form
            varies with the kernel version: compare it folded to 16 bits.
"""
import struct
# Argument markers: CTX is the program context, OUT + k points k bytes into the
# 256-byte scratch buffer of the case program.
CTX = 0x20000000
OUT = 0x40000000


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


MAC_D, MAC_S = bytes.fromhex('020000000002'), bytes.fromhex('020000000001')
A4, B4 = bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2])
A6, B6 = bytes(range(16)), bytes(range(16, 32))


def eth(t):
    return MAC_D + MAC_S + struct.pack('!H', t)


def ip4(proto, payload, opts=b'', frag=0x4000, ttl=64):
    ihl = 5 + len(opts) // 4
    h = bytearray(struct.pack('!BBHHHBBH4s4s', 0x40 | ihl, 0, ihl * 4 + len(payload), 7, frag, ttl,
                              proto, 0, A4, B4) + opts)
    h[10:12] = struct.pack('!H', csum(bytes(h)))
    return bytes(h) + payload


def ip6(nh, payload, hop=64):
    return struct.pack('!IHBB16s16s', 0x60000000, len(payload), nh, hop, A6, B6) + payload


def tcp(opts=b'', flags=0x18):
    doff = 5 + len(opts) // 4
    return struct.pack('!HHIIBBHHH', 1234, 80, 1, 2, doff << 4, flags, 4096, 0x1111, 0) + opts + bytes(range(20))


def udp(n=24, check=0x2222):
    return struct.pack('!HHHH', 5353, 53, 8 + n, check) + bytes(range(n))


icmp4 = struct.pack('!BBHHH', 8, 0, 0, 0x1234, 1) + bytes(range(40))
icmp6 = struct.pack('!BBHHH', 128, 0, 0, 0x4321, 2) + bytes(range(32))
na6 = struct.pack('!BBHI16s', 136, 0, 0, 0x60000000, A6)            # NA, flags S|O set

pkt4 = eth(0x0800) + ip4(6, tcp())
pkt4udp = eth(0x0800) + ip4(17, udp())
pkt4udp0 = eth(0x0800) + ip4(17, udp(check=0))
pkt4icmp = eth(0x0800) + ip4(1, icmp4)
pkt4opt = eth(0x0800) + ip4(6, tcp(opts=bytes([1, 1, 1, 0]) * 2), opts=bytes([1, 1, 1, 0]))
pkt4frag = eth(0x0800) + ip4(17, udp(), frag=0x2000 | 0x10)       # MF, non-zero offset
pkt4vlan = MAC_D + MAC_S + b'\x81\x00\x00\x0a\x08\x00' + ip4(6, tcp())
pkt4in4 = eth(0x0800) + ip4(4, ip4(17, udp()))
pkt6 = eth(0x86dd) + ip6(17, udp())
pkt6tcp = eth(0x86dd) + ip6(6, tcp())
pkt6icmp = eth(0x86dd) + ip6(58, icmp6)
pkt6na = eth(0x86dd) + ip6(58, na6)
pkt6vlan = MAC_D + MAC_S + b'\x81\x00\x00\x0a\x86\xdd' + ip6(17, udp())
pkt6frag = eth(0x86dd) + ip6(44, bytes([17, 0, 0, 1]) + b'\x00\x00\x00\x07' + udp())   # frag hdr, M=1
pkt6ext = eth(0x86dd) + ip6(0, bytes([60, 0]) + bytes(6) + bytes([17, 0]) + bytes(6) + udp())  # HOP, DEST
pkt6in6 = eth(0x86dd) + ip6(41, ip6(17, udp()))
ra6 = struct.pack('!BBHBBHII', 134, 0, 0, 64, 0xc8, 1800, 0, 0)      # RA, M|O, preference high
pkt6ra = eth(0x86dd) + ip6(58, ra6)
pkt6fragext = eth(0x86dd) + ip6(0, bytes([44, 0]) + bytes(6) + bytes([17, 0, 0, 1]) + b'\x00\x00\x00\x07' + udp())  # HOP, frag
mpls4 = eth(0x8847) + struct.pack('!I', 100 << 12 | 1 << 8 | 64) + ip4(17, udp())
arp = eth(0x0806) + struct.pack('!HHBBH6s4s6s4s', 1, 0x0800, 6, 4, 1, MAC_S, A4, bytes(6), B4)
short4 = pkt4[:30]
FF = b'\xff' * 32
MAC = bytes.fromhex('aabbccddeeff')
IN6 = bytes(range(100, 116))
SEGS = b''.join(bytes([0xfc, k] + [k] * 14) for k in range(8))

CASES = [
    # primitives
    ('read_u8', 'ok', pkt4, [CTX, 23, OUT], b''), ('read_u8', 'trunc', short4, [CTX, 40, OUT], FF),
    ('read_be16', 'ok', pkt4, [CTX, 16, OUT], b''), ('read_be16', 'trunc', short4, [CTX, 29, OUT], FF),
    ('read_be32', 'ok', pkt4, [CTX, 26, OUT], b''), ('read_be32', 'trunc', short4, [CTX, 28, OUT], FF),
    ('read_mac', 'ok', pkt4, [CTX, 6, OUT], b''), ('read_mac', 'trunc', short4, [CTX, 26, OUT], FF),
    ('read_in6', 'ok', pkt6, [CTX, 22, OUT], b''), ('read_in6', 'trunc', pkt6[:40], [CTX, 30, OUT], FF),
    ('write_u8', 'ok', pkt4, [CTX, 22, 9], b''), ('write_be16', 'ok', pkt4, [CTX, 34, 0x5000], b''),
    ('write_be32', 'ok', pkt4, [CTX, 30, 0x0a000009], b''), ('write_mac', 'ok', pkt4, [CTX, 0, OUT], MAC),
    ('write_be32', 'trunc', short4, [CTX, 28, 1], b''),
    ('csum_blk', 'ok', pkt4, [CTX, 0, 0, OUT], b''), ('csum_blk', 'trunc', short4, [CTX, 0, 0, OUT], b''),
    # navigation and metadata
    ('eth_next_off', 'plain', pkt4, [CTX, 0, OUT], b''), ('eth_next_off', 'vlan', pkt6vlan, [CTX, 0, OUT], b''),
    ('ipv4_next_off', 'plain', pkt4, [CTX, 14, OUT], b''), ('ipv4_next_off', 'opts', pkt4opt, [CTX, 14, OUT], b''),
    ('ipv4_next_off', 'frag', pkt4frag, [CTX, 14, OUT], b''),
    ('ipv4_next_proto_off', 'plain', pkt4, [CTX, 14, OUT, OUT + 8], b''),
    ('ipv4_next_proto_off', 'opts', pkt4opt, [CTX, 14, OUT, OUT + 8], b''),
    ('ipv6_next_off', 'plain', pkt6, [CTX, 14, OUT], b''), ('ipv6_next_off', 'ext', pkt6ext, [CTX, 14, OUT], b''),
    ('ipv6_next_off', 'frag', pkt6frag, [CTX, 14, OUT], b''),
    ('tcp_next_off', 'plain', pkt4, [CTX, 34, OUT], b''), ('tcp_next_off', 'opts', pkt4opt, [CTX, 38, OUT], b''),
    ('eth_meta', 'plain', pkt4, [CTX, 0, OUT], b''), ('eth_meta', 'vlan', pkt6vlan, [CTX, 0, OUT], b''),
    # find
    ('ctx_find_ipv4', 'plain', pkt4, [CTX, OUT], b''), ('ctx_find_ipv4', 'vlan', pkt4vlan, [CTX, OUT], b''),
    ('ctx_find_ipv6', 'plain', pkt6, [CTX, OUT], b''),
    ('ctx_find_tcp', 'v4', pkt4, [CTX, OUT], b''), ('ctx_find_tcp', 'v6', pkt6tcp, [CTX, OUT], b''),
    ('ctx_find_tcp', 'mismatch', pkt4udp, [CTX, OUT], b''),
    ('ctx_find_udp', 'v4', pkt4udp, [CTX, OUT], b''), ('ctx_find_udp', 'v6', pkt6, [CTX, OUT], b''),
    ('ctx_find_udp', 'v6vlan', pkt6vlan, [CTX, OUT], b''), ('ctx_find_udp', 'v6ext', pkt6ext, [CTX, OUT], b''),
    ('ctx_find_icmp4', 'ok', pkt4icmp, [CTX, OUT], b''), ('ctx_find_icmp6', 'ok', pkt6icmp, [CTX, OUT], b''),
    # incremental and full checksums
    ('ipv4_recompute_csum', 'ok', pkt4, [CTX, 14], b''),
    ('tcp_recompute_csum_v4', 'ok', pkt4, [CTX, 34, 14], b''),
    ('tcp_recompute_csum_v6', 'ok', pkt6tcp, [CTX, 54, 14], b''),
    ('udp_recompute_csum_v4', 'ok', pkt4udp, [CTX, 34, 14], b''),
    ('udp_recompute_csum_v6', 'ok', pkt6, [CTX, 54, 14], b''),
    ('icmp4_recompute_csum', 'ok', pkt4icmp, [CTX, 34, len(icmp4)], b''),
    ('icmp6_recompute_csum', 'ok', pkt6icmp, [CTX, 54, 14, len(icmp6)], b''),
    # setters
    ('ipv4_set_tos', 'ok', pkt4, [CTX, 14, 0x10], b''), ('ipv4_set_ttl', 'ok', pkt4, [CTX, 14, 3], b''),
    ('ipv4_dec_ttl', 'ok', pkt4, [CTX, 14, OUT], b''),
    ('ipv4_set_protocol', 'ok', pkt4, [CTX, 14, 17], b''),
    ('ipv4_set_frag_flag', 'df_off', pkt4, [CTX, 14, 0x4000, 0], b''),
    ('ipv4_set_frag_flag', 'mf_on', pkt4, [CTX, 14, 0x2000, 1], b''),
    ('ipv4_set_addr', 'tcp', pkt4, [CTX, 14, 0x0b00000a, 1], b''),
    ('ipv4_set_addr', 'udp0', pkt4udp0, [CTX, 14, 0x0b00000a, 0], b''),
    ('ipv6_dec_hop_limit', 'ok', pkt6, [CTX, 14, OUT], b''),
    ('ipv6_set_addr', 'udp', pkt6, [CTX, 14, OUT, 1], IN6), ('ipv6_set_addr', 'tcp', pkt6tcp, [CTX, 14, OUT, 0], IN6),
    ('ipv6_set_addr', 'ext', pkt6ext, [CTX, 14, OUT, 1], IN6),
    ('ipv6_set_frag_flag', 'm_off', pkt6frag, [CTX, 14, 1, 0], b''),
    ('tcp_set_port', 'dst', pkt4, [CTX, 34, 0x5000, 1], b''), ('tcp_set_seq', 'seq', pkt4, [CTX, 34, 0x11223344, 0], b''),
    ('tcp_set_seq', 'ack', pkt4, [CTX, 34, 0x55667788, 1], b''), ('tcp_set_flag', 'syn', pkt4, [CTX, 34, 0x0002, 1], b''),
    ('udp_set_port', 'src', pkt4udp, [CTX, 34, 0x1111, 0], b''), ('udp_set_port', 'csum0', pkt4udp0, [CTX, 34, 0x2222, 1], b''),
    ('icmp_set_typecode', 'type', pkt4icmp, [CTX, 34, 0, 0], b''),
    ('icmp_set_echo', 'seq', pkt4icmp, [CTX, 34, 0x9999, 1], b''), ('icmp_set_echo', 'id', pkt4icmp, [CTX, 34, 0x7777, 0], b''),
    ('icmp6_set_advert_flag', 'override_off', pkt6na, [CTX, 54, 0x20, 0, 1], b''),
    ('ipv4_set_total_len', 'ok', pkt4, [CTX, 14, 70], b''), ('ipv4_set_total_len', 'udp', pkt4udp, [CTX, 14, 60], b''),
    ('ipv4_set_id', 'ok', pkt4, [CTX, 14, 0x1234], b''), ('ipv4_set_frag_off', 'ok', pkt4, [CTX, 14, 0x2000], b''),
    ('ipv4_set_hlen', 'ok', pkt4opt, [CTX, 14, 20], b''), ('ipv4_set_hlen_raw', 'ok', pkt4opt, [CTX, 14, 24], b''),
    ('tcp_set_flags', 'ok', pkt4, [CTX, 34, 0x12], b''), ('tcp_set_flags_raw', 'ok', pkt4, [CTX, 34, 0x12], b''),
    ('tcp_set_window', 'ok', pkt4, [CTX, 34, 0x4000], b''), ('tcp_set_urg_ptr', 'ok', pkt4, [CTX, 34, 7], b''),
    ('tcp_set_doff', 'ok', pkt4opt, [CTX, 38, 5], b''), ('tcp_set_doff_raw', 'ok', pkt4opt, [CTX, 38, 6], b''),
    ('udp_set_len', 'ok', pkt4udp, [CTX, 34, 30], b''),
    ('ipv6_set_payload_len', 'udp', pkt6, [CTX, 14, 30], b''), ('ipv6_set_payload_len', 'ext', pkt6ext, [CTX, 14, 46], b''),
    ('ipv6_set_vtcflow', 'tc', pkt6, [CTX, 14, 0x0ff00000, 0x02a00000], b''),
    ('icmp6_ra_flags', 'ok', pkt6ra, [CTX, 54, OUT], b''), ('icmp6_na_flags', 'ok', pkt6na, [CTX, 54, OUT], b''),
    ('icmp6_set_ra_pref', 'ok', pkt6ra, [CTX, 54, 3], b''),
    ('arp_get_sha', 'ok', arp, [CTX, 14, OUT], b''), ('arp_set_sha', 'ok', arp, [CTX, 14, OUT], MAC),
    ('arp_get_spa', 'ok', arp, [CTX, 14, OUT], b''), ('arp_set_spa', 'ok', arp, [CTX, 14, 0x0900000a], b''),
    ('arp_get_tha', 'ok', arp, [CTX, 14, OUT], b''), ('arp_set_tha', 'ok', arp, [CTX, 14, OUT], MAC),
    ('arp_get_tpa', 'ok', arp, [CTX, 14, OUT], b''), ('arp_set_tpa', 'ok', arp, [CTX, 14, 0x0900000a], b''),
    ('arp_hlen', 'ok', arp, [CTX, 14, OUT], b''), ('arp_is_eth_ipv4', 'ok', arp, [CTX, 14, OUT], b''),
    ('ctx_find_arp', 'ok', arp, [CTX, OUT], b''),
    ('mpls_set_lse', 'ttl', mpls4, [CTX, 14, 0xff, 9], b''), ('mpls_next_ip', 'v4', mpls4, [CTX, 14, 4], b''),
    ('eth_set_ethertype', 'plain', pkt4, [CTX, 0, 0x86dd], b''), ('eth_set_ethertype', 'vlan', pkt6vlan, [CTX, 0, 0x0800], b''),
    ('eth_vlan_tci', 'get', pkt6vlan, [CTX, 0, 0, 0, OUT], b''), ('eth_vlan_tci', 'set', pkt6vlan, [CTX, 0, 0, 0x0fff0123, OUT], b''),
    ('eth_info', 'plain', pkt4, [CTX, 0, OUT], b''), ('eth_info', 'vlan', pkt6vlan, [CTX, 0, OUT], b''),
    ('ipv6_next_proto_off', 'plain', pkt6, [CTX, 14, OUT, OUT + 8], b''),
    ('ipv6_next_proto_off', 'ext', pkt6ext, [CTX, 14, OUT, OUT + 8], b''),
    ('ipv6_ext_depth', 'ext', pkt6ext, [CTX, 14, OUT], b''),
    ('ipv6_has_frag_hdr', 'plain', pkt6, [CTX, 14, OUT], b''), ('ipv6_has_frag_hdr', 'frag', pkt6frag, [CTX, 14, OUT], b''),
    ('ipv6_is_frag', 'frag', pkt6frag, [CTX, 14, OUT], b''),
    ('ipv6_frag_off_flags', 'frag', pkt6frag, [CTX, 14, OUT], b''), ('ipv6_frag_off_flags', 'ext', pkt6fragext, [CTX, 14, OUT], b''),
    ('ipv6_l4_meta', 'ext', pkt6ext, [CTX, 14, OUT], b''),
    # FIB (the lookup result depends on the routing table, see COMPARE)
    ('ipv4_fib_lookup', 'ok', pkt4, [CTX, 14, OUT], b''), ('ipv4_fib_lookup', 'trunc', short4, [CTX, 14, OUT], b''),
    ('ipv6_fib_lookup', 'ok', pkt6, [CTX, 14, OUT], b''),
    # insert / remove (move the packet start with bpf_xdp_adjust_head)
    ('eth_insert_vlan', 'ok', pkt4, [CTX, 0, 0x8100, 10], b''),
    ('eth_insert_mpls', 'ok', pkt4, [CTX, 0, 100, 1, 64], b''),
    ('eth_insert_ipv4', 'ok', pkt4, [CTX, 0, 4, 0x0300000a, 0x0400000a], b''),
    ('eth_insert_ipv6', 'ok', pkt6, [CTX, 0, 41, OUT, OUT + 16], IN6 + IN6[::-1]),
    ('eth_remove_vlan', 'ok', pkt6vlan, [CTX, 0], b''),
    ('eth_remove_ipv4', 'ok', pkt4in4, [CTX, 0], b''), ('eth_remove_ipv6', 'ok', pkt6in6, [CTX, 0], b''),
    ('ipv6_insert_srh', 'n1', pkt6, [CTX, 14, OUT, 1], SEGS), ('ipv6_insert_srh', 'n2', pkt6, [CTX, 14, OUT, 2], SEGS),
    ('ipv6_insert_srh', 'n8', pkt6, [CTX, 14, OUT, 8], SEGS),
]

COMPARE = {'ipv4_fib_lookup': 'no_out', 'ipv6_fib_lookup': 'no_out',
           'csum_blk': 'csum32'}

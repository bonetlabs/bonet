"""Cases for every public API: packets, view offsets, arguments, NULL pointers.

For each API, cases() returns (label, packet, io) tuples, io being the
bnt_api_io content before the call (model.IO). The cases are built from:
  - a corpus of packets, each with the offset of every header it carries; the
    API's views point at the matching header, or at the L3 offset when the
    packet has none (a wrong-protocol case);
  - the API's main packet cut at every length (the truncation sweep);
  - each pointer parameter NULL in turn;
  - view offsets past the packet, up to 0xffff, the largest a parse accepts
    (larger ones go to the parse functions);
  - boundary values of the scalar arguments.
"""
import struct

from model import IO, SLOT, csum16, kind

MAC_D, MAC_S = bytes.fromhex('020000000002'), bytes.fromhex('020000000001')
A4, B4 = bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2])
A6, B6 = bytes.fromhex('20010db8000000000000000000000001'), bytes.fromhex('20010db8000000000000000000000002')
SEGS = b''.join(bytes([0xfc, k] + [k] * 14) for k in range(8))
PAY = bytes(range(32))


def eth(t, tags=()):
    return MAC_D + MAC_S + b''.join(struct.pack('!HH', tp, tci) for tp, tci in tags) + struct.pack('!H', t)


def ip4(proto, payload, opts=b'', frag=0x4000, ttl=64, tot=None, vihl=None, tos=0x10):
    ihl = 5 + len(opts) // 4
    h = bytearray(struct.pack('!BBHHHBBH4s4s', vihl if vihl is not None else 0x40 | ihl, tos,
                              tot if tot is not None else ihl * 4 + len(payload), 0x1234, frag, ttl, proto, 0,
                              A4, B4) + opts)
    h[10:12] = struct.pack('!H', csum16(bytes(h)))
    return bytes(h) + payload


def ip6(nh, payload, hop=64, first=0x6abcdef1):
    return struct.pack('!IHBB16s16s', first, len(payload), nh, hop, A6, B6) + payload


def ph4(proto, n):
    return A4 + B4 + bytes([0, proto]) + struct.pack('!H', n)


def ph6(proto, n):
    return A6 + B6 + struct.pack('!I', n) + bytes([0, 0, 0, proto])


def tcp(ph, opts=b'', flags=0x18, doff=None):
    d = doff if doff is not None else 5 + len(opts) // 4
    h = bytearray(struct.pack('!HHIIBBHHH', 1234, 80, 0x11223344, 0x55667788, d << 4 | flags >> 8, flags & 0xff,
                                  4096, 0, 7) + opts)
    seg = bytes(h) + PAY
    if ph is not None:
        h[16:18] = struct.pack('!H', csum16(ph(6, len(seg)) + seg))
    return bytes(h) + PAY


def udp(ph, check=True, n=24):
    h = bytearray(struct.pack('!HHHH', 5353, 53, 8 + n, 0))
    seg = bytes(h) + PAY[:n]
    if check and ph is not None:
        c = csum16(ph(17, len(seg)) + seg) or 0xffff
        h[6:8] = struct.pack('!H', c)
    return bytes(h) + PAY[:n]


def udp_csum0():
    """A UDP segment (IPv4 pseudo-header) whose checksum computes to 0, so it
    is sent as 0xffff: the last two payload bytes are chosen for it."""
    h = bytearray(struct.pack('!HHHH', 5353, 53, 8 + 24, 0))
    pay = bytearray(PAY[:22] + bytes(2))
    s = 0xffff - csum16(ph4(17, 32) + bytes(h) + bytes(pay))   # ones' complement sum without the two bytes
    pay[22:24] = struct.pack('!H', (0xffff - s) % 0xffff or 0xffff)
    assert csum16(ph4(17, 32) + bytes(h) + bytes(pay)) == 0
    h[6:8] = b'\xff\xff'
    return bytes(h) + bytes(pay)


def icmp4(t=8, code=0):
    h = bytearray(struct.pack('!BBHHH', t, code, 0, 0x4321, 7) + PAY)
    h[2:4] = struct.pack('!H', csum16(bytes(h)))
    return bytes(h)


def icmp6(body, t=128, code=0):
    h = bytearray(struct.pack('!BBH', t, code, 0) + body)
    h[2:4] = struct.pack('!H', csum16(ph6(58, len(h)) + bytes(h)))
    return bytes(h)


def udp_n(pay):
    h = bytearray(struct.pack('!HHHH', 5353, 53, 8 + len(pay), 0))
    h[6:8] = struct.pack('!H', csum16(ph4(17, 8 + len(pay)) + bytes(h) + pay) or 0xffff)
    return bytes(h) + pay


def tcp_n(pay):
    h = bytearray(struct.pack('!HHIIBBHHH', 1, 2, 3, 4, 0x50, 0x10, 512, 0, 0))
    h[16:18] = struct.pack('!H', csum16(ph4(6, 20 + len(pay)) + bytes(h) + pay))
    return bytes(h) + pay


def icmp4_n(pay):
    h = bytearray(struct.pack('!BBHHH', 8, 0, 0, 1, 2) + pay)
    h[2:4] = struct.pack('!H', csum16(bytes(h)))
    return bytes(h)


ECHO6 = struct.pack('!HH', 0x4321, 7) + PAY
RA = bytes([64, 0x80 | 0x40 | 0x08 | 0x04]) + struct.pack('!HII', 1800, 0, 0)   # M, O, pref high, proxy
NA = bytes([0x40 | 0x20, 0, 0, 0]) + A6                                          # S, O
ARP = struct.pack('!HHBBH6s4s6s4s', 1, 0x0800, 6, 4, 1, MAC_S, A4, bytes(6), B4)
ARP_TR = struct.pack('!HHBBH', 6, 0x0800, 6, 4, 1) + MAC_S + A4 + bytes(6) + B4  # htype 6
ARP_LONG = struct.pack('!HHBBH', 1, 0x0800, 8, 4, 1) + bytes(8) + A4 + bytes(8) + B4  # hln 8


def ext(nh, n8=0):
    """IPv6 extension header (HOP/DEST/ROUTING form) of 8 * (n8 + 1) bytes."""
    return bytes([nh, n8]) + bytes(6 + 8 * n8)


def frag6(nh, off=0, m=0):
    return bytes([nh, 0]) + struct.pack('!HI', off << 3 | m, 0x99)


def ah(nh):
    return bytes([nh, 2, 0, 0]) + bytes(12)   # (2 + 2) * 4 = 16 bytes


def mpls(label, tc=0, bos=0, ttl=64):
    return struct.pack('!I', label << 12 | tc << 9 | bos << 8 | ttl)


def P(layers, data):
    """A corpus entry: header offsets by view type, and the bytes."""
    return dict(off=layers, data=data)


V6U = udp(ph6)
V6T = tcp(ph6)


def corpus():
    c = {}
    l4 = 14 + 20
    c['v4tcp'] = P(dict(eth=0, ipv4=14, tcp=l4), eth(0x0800) + ip4(6, tcp(ph4)))
    c['v4tcp_opts'] = P(dict(eth=0, ipv4=14, tcp=l4 + 8),
                        eth(0x0800) + ip4(6, tcp(ph4, opts=bytes([1, 1, 1, 0]) * 3), opts=bytes([1, 1, 1, 0]) * 2))
    c['v4tcp_syn'] = P(dict(eth=0, ipv4=14, tcp=l4), eth(0x0800) + ip4(6, tcp(ph4, flags=0x1c3)))
    c['v4udp'] = P(dict(eth=0, ipv4=14, udp=l4), eth(0x0800) + ip4(17, udp(ph4)))
    c['v4udp_nocsum'] = P(dict(eth=0, ipv4=14, udp=l4), eth(0x0800) + ip4(17, udp(ph4, check=False)))
    c['v4icmp'] = P(dict(eth=0, ipv4=14, icmp4=l4), eth(0x0800) + ip4(1, icmp4()))
    c['v4icmp_unreach'] = P(dict(eth=0, ipv4=14, icmp4=l4), eth(0x0800) + ip4(1, icmp4(3, 1)))
    c['v4frag_first'] = P(dict(eth=0, ipv4=14, udp=l4), eth(0x0800) + ip4(17, udp(ph4), frag=0x2000))
    c['v4frag_later'] = P(dict(eth=0, ipv4=14), eth(0x0800) + ip4(17, PAY, frag=0x2000 | 0x10))
    c['v4frag_last'] = P(dict(eth=0, ipv4=14), eth(0x0800) + ip4(6, PAY, frag=0x10))
    c['v4_rf'] = P(dict(eth=0, ipv4=14, tcp=l4), eth(0x0800) + ip4(6, tcp(ph4), frag=0x8000))
    c['v4_ttl1'] = P(dict(eth=0, ipv4=14, udp=l4), eth(0x0800) + ip4(17, udp(ph4), ttl=1))
    c['v4_ttl0'] = P(dict(eth=0, ipv4=14, udp=l4), eth(0x0800) + ip4(17, udp(ph4), ttl=0))
    c['v4ipip'] = P(dict(eth=0, ipv4=14, udp=l4 + 20), eth(0x0800) + ip4(4, ip4(17, udp(ph4))))
    c['v4in6'] = P(dict(eth=0, ipv4=14, ipv6=l4), eth(0x0800) + ip4(41, ip6(17, V6U)))
    c['v4gre'] = P(dict(eth=0, ipv4=14), eth(0x0800) + ip4(47, PAY))
    c['v4_ver5'] = P(dict(eth=0, ipv4=14), eth(0x0800) + ip4(6, tcp(ph4), vihl=0x55))
    c['v4_ihl4'] = P(dict(eth=0, ipv4=14), eth(0x0800) + ip4(6, tcp(ph4), vihl=0x44))
    c['v4_ihl15'] = P(dict(eth=0, ipv4=14), eth(0x0800) + ip4(6, tcp(ph4), vihl=0x4f))
    c['v4_totshort'] = P(dict(eth=0, ipv4=14), eth(0x0800) + ip4(6, tcp(ph4), tot=19))
    c['v4_tcp_doff4'] = P(dict(eth=0, ipv4=14, tcp=l4), eth(0x0800) + ip4(6, tcp(ph4, doff=4)))
    c['v4_tcp_doff15'] = P(dict(eth=0, ipv4=14, tcp=l4), eth(0x0800) + ip4(6, tcp(ph4, doff=15)))
    c['vlan1_v4tcp'] = P(dict(eth=0, ipv4=18, tcp=38), eth(0x0800, [(0x8100, 0x100a)]) + ip4(6, tcp(ph4)))
    c['qinq_v4udp'] = P(dict(eth=0, ipv4=22, udp=42),
                        eth(0x0800, [(0x88a8, 0x0064), (0x8100, 0x300a)]) + ip4(17, udp(ph4)))
    c['vlan3'] = P(dict(eth=0), eth(0x0800, [(0x8100, 1), (0x8100, 2), (0x8100, 3)]) + ip4(17, udp(ph4)))
    c['vlan1_v6udp'] = P(dict(eth=0, ipv6=18, udp=58), eth(0x86dd, [(0x8100, 5)]) + ip6(17, V6U))
    c['vlan1_arp'] = P(dict(eth=0, arp=18), eth(0x0806, [(0x8100, 5)]) + ARP)
    c['v6udp'] = P(dict(eth=0, ipv6=14, udp=54), eth(0x86dd) + ip6(17, V6U))
    c['v6udp_nocsum'] = P(dict(eth=0, ipv6=14, udp=54), eth(0x86dd) + ip6(17, udp(ph6, check=False)))
    c['v6tcp'] = P(dict(eth=0, ipv6=14, tcp=54), eth(0x86dd) + ip6(6, V6T))
    c['v6echo'] = P(dict(eth=0, ipv6=14, icmp6=54), eth(0x86dd) + ip6(58, icmp6(ECHO6)))
    c['v6ra'] = P(dict(eth=0, ipv6=14, icmp6=54), eth(0x86dd) + ip6(58, icmp6(RA, 134)))
    c['v6na'] = P(dict(eth=0, ipv6=14, icmp6=54), eth(0x86dd) + ip6(58, icmp6(NA, 136)))
    c['v6ext2'] = P(dict(eth=0, ipv6=14, udp=54 + 24), eth(0x86dd) + ip6(0, ext(60) + ext(17, 1) + V6U))
    c['v6ah'] = P(dict(eth=0, ipv6=14, tcp=54 + 16), eth(0x86dd) + ip6(51, ah(6) + V6T))
    c['v6srh'] = P(dict(eth=0, ipv6=14, udp=54 + 40), eth(0x86dd) + ip6(43, bytes([17, 4, 4, 1, 1, 0, 0, 0]) +
                                                                   SEGS[:32] + V6U))
    c['v6frag_first'] = P(dict(eth=0, ipv6=14, udp=62), eth(0x86dd) + ip6(44, frag6(17, 0, 1) + V6U))
    c['v6frag_atomic'] = P(dict(eth=0, ipv6=14, tcp=62), eth(0x86dd) + ip6(44, frag6(6, 0, 0) + V6T))
    c['v6frag_later'] = P(dict(eth=0, ipv6=14), eth(0x86dd) + ip6(44, frag6(17, 3, 1) + PAY))
    c['v6frag_later_ext'] = P(dict(eth=0, ipv6=14), eth(0x86dd) + ip6(44, frag6(60, 3, 0) + PAY))
    c['v6frag_tcp'] = P(dict(eth=0, ipv6=14, tcp=62), eth(0x86dd) + ip6(44, frag6(6, 0, 1) + V6T))
    c['v6frag_icmp6'] = P(dict(eth=0, ipv6=14, icmp6=62), eth(0x86dd) + ip6(44, frag6(58, 0, 1) + icmp6(ECHO6)))
    # the rest of the chain is bad after a first fragment: the fragment APIs stop before it
    c['v6frag_then_trunc'] = P(dict(eth=0, ipv6=14), eth(0x86dd) + ip6(44, frag6(43, 0, 1)))   # Routing announced, missing
    c['v6frag_then_deep'] = P(dict(eth=0, ipv6=14), eth(0x86dd) + ip6(0, ext(44) + frag6(60, 0, 1) +
                                                                       ext(60) * 5 + ext(17) + V6U))
    six = ext(60) + ext(60) + ext(60) + ext(60) + ext(60) + ext(17)
    c['v6ext6'] = P(dict(eth=0, ipv6=14, udp=54 + 48), eth(0x86dd) + ip6(0, six + V6U))
    c['v6ext7'] = P(dict(eth=0, ipv6=14), eth(0x86dd) + ip6(0, ext(60) * 6 + ext(17) + V6U))
    c['v6ext_trunc'] = P(dict(eth=0, ipv6=14), eth(0x86dd) + ip6(60, bytes([17, 30]) + bytes(14)))
    c['v6in6'] = P(dict(eth=0, ipv6=14, udp=94), eth(0x86dd) + ip6(41, ip6(17, V6U)))
    c['v6ip4'] = P(dict(eth=0, ipv6=14, ipv4=54), eth(0x86dd) + ip6(4, ip4(17, udp(ph4))))
    c['v6_ver4'] = P(dict(eth=0, ipv6=14), eth(0x86dd) + ip6(17, V6U, first=0x4abcdef1))
    c['v6_hop1'] = P(dict(eth=0, ipv6=14, udp=54), eth(0x86dd) + ip6(17, V6U, hop=1))
    c['v6_nonext'] = P(dict(eth=0, ipv6=14), eth(0x86dd) + ip6(59, PAY))
    c['arp'] = P(dict(eth=0, arp=14), eth(0x0806) + ARP + bytes(18))
    c['arp_tr'] = P(dict(eth=0, arp=14), eth(0x0806) + ARP_TR + bytes(18))
    c['arp_long'] = P(dict(eth=0, arp=14), eth(0x0806) + ARP_LONG + bytes(10))
    # header of 8 + 2 * (120 + 8) = 264 bytes: past the bound on a following offset
    c['arp_huge'] = P(dict(eth=0, arp=14), eth(0x0806) + struct.pack('!HHBBH', 1, 0x0800, 120, 8, 1) + bytes(256))
    c['v4udp_csum0'] = P(dict(eth=0, ipv4=14, udp=34), eth(0x0800) + ip4(17, udp_csum0()))
    c['mpls1_v4'] = P(dict(eth=0, mpls=14, ipv4=18), eth(0x8847) + mpls(100, 5, 1) + ip4(17, udp(ph4)))
    c['mpls2_v6'] = P(dict(eth=0, mpls=14, ipv6=22), eth(0x8847) + mpls(100, 1) + mpls(200, 2, 1) + ip6(17, V6U))
    c['mpls_mc'] = P(dict(eth=0, mpls=14), eth(0x8848) + mpls(0xfffff, 7, 1, 255) + bytes(46))
    c['mpls_bos_junk'] = P(dict(eth=0, mpls=14), eth(0x8847) + mpls(3, 0, 1) + bytes([0x50]) + bytes(45))
    c['vlan1_mpls'] = P(dict(eth=0, mpls=18, ipv4=22), eth(0x8847, [(0x8100, 7)]) + mpls(16, 0, 1) +
                        ip4(17, udp(ph4)))
    c['mpls1_v6'] = P(dict(eth=0, mpls=14, ipv6=18), eth(0x8847) + mpls(300, 3, 1) + ip6(17, V6U))
    pad = bytes(52)  # headers further in than the 64-byte prefix the inserts and removes move
    c['deep_vlan'] = P(dict(eth=52, ipv4=70), pad + eth(0x0800, [(0x8100, 9)]) + ip4(17, udp(ph4)))
    c['deep_v4ipip'] = P(dict(eth=52, ipv4=66), pad + eth(0x0800) + ip4(4, ip4(17, udp(ph4))))
    for n in (0, 1, 2, 3, 5, 31, 61, 64, 65, 100, 129, 1000):  # checksum ranges: 64-byte blocks, words, tail
        pay = bytes((i * 7 + 3) & 0xff for i in range(n))
        c[f'v4udp_len{n}'] = P(dict(eth=0, ipv4=14, udp=34), eth(0x0800) + ip4(17, udp_n(pay)))
        c[f'v4tcp_len{n}'] = P(dict(eth=0, ipv4=14, tcp=34), eth(0x0800) + ip4(6, tcp_n(pay)))
        c[f'v4icmp_len{n}'] = P(dict(eth=0, ipv4=14, icmp4=34), eth(0x0800) + ip4(1, icmp4_n(pay)))
    c['lldp'] = P(dict(eth=0), eth(0x88cc) + bytes(50))
    c['runt60'] = P(dict(eth=0, ipv4=14, udp=34), eth(0x0800) + ip4(17, udp(ph4, n=18)))
    c['vlan1_runt60'] = P(dict(eth=0, ipv4=18, udp=38), eth(0x0800, [(0x8100, 7)]) + ip4(17, udp(ph4, n=14)))
    c['short63'] = P(dict(eth=0, ipv4=14, udp=34), eth(0x0800) + ip4(17, udp(ph4, n=21)))
    c['v4big'] = P(dict(eth=0, ipv4=14, udp=34), eth(0x0800) + ip4(17, udp(ph4, n=1400)))
    c['v4huge'] = P(dict(eth=0, ipv4=14, udp=34), eth(0x0800) + ip4(17, udp(ph4, n=1500)))
    # IPv6 chains: every extension type (and fragment kind) at every position up
    # to the depth limit, and every kind of terminal header after a chain
    kinds = {'hop': (0, lambda nx: ext(nx)), 'rt': (43, lambda nx: ext(nx, 1)), 'dst': (60, lambda nx: ext(nx)),
             'ah': (51, lambda nx: ah(nx)), 'frag0': (44, lambda nx: frag6(nx, 0, 1)),
             'fragn': (44, lambda nx: frag6(nx, 5, 0)), 'mob': (135, lambda nx: ext(nx)),
             'hip': (139, lambda nx: ext(nx, 1)), 'shim': (140, lambda nx: ext(nx))}
    terms = {'udp': (17, V6U), 'tcp': (6, V6T), 'icmp6': (58, icmp6(ECHO6)), 'sctp': (132, PAY), 'none': (59, PAY),
             'v4': (4, ip4(17, udp(ph4))), 'v6': (41, ip6(17, V6U))}
    for depth in range(1, 7):
        for kn, (kt, mk) in kinds.items():
            chain = [(60, lambda nx: ext(nx))] * (depth - 1) + [(kt, mk)]
            for tn, (tt, tb) in terms.items():
                if tn not in ('udp', 'sctp') and (kn != 'dst' or depth not in (1, 6)):
                    continue
                body, nxt = tb, tt
                for t, f in reversed(chain):
                    body, nxt = f(nxt) + body, t
                n = sum(len(f(0)) for t, f in chain)
                offs = dict(eth=0, ipv6=14)
                if tn in ('udp', 'tcp', 'icmp6') and kn != 'fragn':
                    offs[tn] = 54 + n
                c[f'chain{depth}_{kn}_{tn}'] = P(offs, eth(0x86dd) + ip6(chain[0][0] if depth > 1 else kt, body))
    for tags, tag in (([(0x8100, 1), (0x8100, 2)], 'aa'), ([(0x88a8, 1), (0x88a8, 2)], 'qq'),
                      ([(0x8100, 1), (0x88a8, 2)], 'aq'), ([(0x88a8, 1), (0x8100, 2), (0x88a8, 3)], 'qaq'),
                      ([(0x8100, 1), (0x8100, 2), (0x8100, 3)], 'aaa')):
        c[f'tags_{tag}'] = P(dict(eth=0, ipv4=14 + 4 * len(tags), udp=34 + 4 * len(tags)) if len(tags) < 3 else
                             dict(eth=0), eth(0x0800, tags) + ip4(17, udp(ph4)))
    # every L3 variant behind one and two VLAN tags too: the walks are unrolled
    # per VLAN depth, so each depth has its own copy of the L3 code
    for name, e in list(c.items()):
        if e['off'].get('eth') != 0 or e['data'][12:14] in (b'\x81\x00', b'\x88\xa8') or 'arp' in name or \
                name.startswith('chain') and not name.endswith('_udp'):
            continue
        for tags, tag in (([(0x8100, 0x0123)], 'v1'), ([(0x88a8, 0x0064), (0x8100, 0x1123)], 'v2')):
            d = e['data']
            c[f'{tag}_{name}'] = P({k: (o if k == 'eth' else o + 4 * len(tags)) for k, o in e['off'].items()},
                                   d[:12] + b''.join(struct.pack('!HH', *t) for t in tags) + d[12:])
    for name, e in c.items():
        assert len(e['data']) <= 4096, name
    return c


CORPUS = corpus()
L3_OFF = {name: e['off'].get('ipv4', e['off'].get('ipv6', e['off'].get('arp', e['off'].get('mpls', 14))))
          for name, e in CORPUS.items()}
# the packet each view type's truncation sweep cuts
MAIN = {'eth': 'qinq_v4udp', 'ipv4': 'v4tcp_opts', 'ipv6': 'v6ext2', 'tcp': 'v4tcp_opts', 'udp': 'v4udp',
        'icmp4': 'v4icmp', 'icmp6': 'v6ra', 'arp': 'arp', 'mpls': 'mpls2_v6', 'ctx': 'qinq_v4udp'}
MAIN_BY_API = {'bnt_icmp6__get_neighbor_advert_flags': 'v6na', 'bnt_ipv6__insert_srh': 'v6udp',
               'bnt_eth__remove_vlan': 'qinq_v4udp', 'bnt_eth__remove_ipv4': 'v4ipip',
               'bnt_eth__remove_ipv6': 'v6in6', 'bnt_eth__insert_vlan': 'vlan1_v4tcp',
               'bnt_ctx__find_ipv6': 'v6ext2', 'bnt_ctx__find_icmp6': 'v6echo', 'bnt_ctx__find_icmp4': 'v4icmp',
               'bnt_ctx__find_arp': 'arp', 'bnt_ctx__find_mpls': 'mpls2_v6', 'bnt_ctx__find_tcp': 'v4tcp_opts'}
for _f in ('neighbor_advert_router', 'neighbor_advert_solicited', 'neighbor_advert_override'):
    for _a in ('set', 'clear', 'is'):
        MAIN_BY_API[f'bnt_icmp6__{_a}_{_f}'] = 'v6na'

# more packets cut at every length, for the walks that go deep
EXTRA_CUTS = {'ctx': ('v2_v6ext6', 'v2_v6frag_first', 'v1_v4tcp_opts', 'v2_v6ah', 'v1_v6echo', 'v2_arp' if False else
                      'vlan1_arp', 'v1_mpls1_v4'),
              'ipv6': ('v6ext6', 'v6ah', 'v6frag_first', 'v6srh'), 'eth': ('vlan1_v4tcp', 'v4ipip', 'v6in6'),
              'ipv4': ('v4ipip',), 'arp': ('arp_long',)}

SENTINEL = 0x5a5a  # initial offset of an output view: still there means untouched
FILL = 0xa5        # initial content of the pointer arguments, to see what gets cleared


def view_type(t):
    return t.replace('const ', '').replace('bnt_', '').rstrip(' *')


def arg_values(name, t, k):
    """Boundary values of scalar argument k of name."""
    if 'vlan' in name and k == 1:
        return [0, 1, 2, 3, 0xffffffff]
    if name.endswith('set_label') or name.endswith('insert_mpls') and k == 1:
        return [0, 16, 0xfffff, 0x100000]
    if name.endswith('set_doff') or name.endswith('set_doff_no_csum'):
        return [4, 5, 8, 15, 16]
    if 'set_hlen' in name:
        return [16, 20, 22, 24, 60, 64]
    if name.endswith('set_router_advert_preference'):
        return [0, 1, 3, 4, 0xff]
    if name.endswith('insert_srh') and k == 2:
        return list(range(10))
    if name.endswith('recompute_csum') and t == '__u16':
        return [0, 1, 2, 3, 4, 8, 40, 63, 64, 65, 128, 1499, 1500, 1501, 0xffff]
    if t == '_Bool':
        return [0, 1, 0x100]
    if t == '__u8':
        return [0, 1, 0x7f, 0xff]
    if t == '__u16':
        return [0, 1, 0x8000, 0xffff]
    return [0, 1, 0x80000000, 0xffffffff]


def default_arg(name, t, k):
    vals = arg_values(name, t, k)
    if 'vlan' in name and k == 1:
        return 0
    if name.endswith('insert_srh'):
        return 2
    if name.endswith('recompute_csum') and t == '__u16':
        return 40
    if 'set_hlen' in name:
        return 24
    if name.endswith(('set_doff', 'set_doff_no_csum')):
        return 8
    if name.endswith(('insert_vlan',)):
        return [0x8100, 0x2005][k - 1]
    return vals[2] if len(vals) > 2 else vals[-1]


def fib_struct(status=0):
    f = bytearray(68)
    f[0:2] = b'\x02\x06'
    f[8:12] = (3).to_bytes(4, 'little')
    f[52:58], f[58:64] = MAC_S, MAC_D
    f[64:68] = status.to_bytes(4, 'little', signed=True)
    return bytes(f)


def io_pack(arg=(0,) * 4, off=(0,) * 4, nullmask=0, buf=None):
    return IO.pack(*arg, *off, nullmask, -999, *([0] * 8), bytes(buf) if buf else bytes(4 * SLOT))


def base_buf(name, sig):
    """Pointer arguments: inputs get their value, outputs the FILL pattern."""
    b = bytearray([FILL]) * (4 * SLOT)
    for k, t in enumerate(sig['params']):
        tt = t.replace('const ', '')
        if kind(t) != 'ptr':
            continue
        if 'fib' in name.split('__')[0]:
            b[k * SLOT:k * SLOT + 68] = fib_struct()
        elif t.startswith('const ') and tt == 'unsigned char *':
            b[k * SLOT:k * SLOT + 6] = bytes.fromhex('0a0b0c0d0e0f')
        elif t.startswith('const ') and tt == 'struct in6_addr *':
            if name.endswith('insert_srh'):
                b[k * SLOT:k * SLOT + 128] = SEGS
            else:
                b[k * SLOT:k * SLOT + 16] = bytes.fromhex('fd000000000000000000000000000099') if k == 1 else A6
    return b


def cases(name, sig):
    params = sig['params']
    kinds = [kind(t) for t in params]
    vtypes = {k: view_type(t) for k, t in enumerate(params) if kinds[k] == 'view'}
    in_view = 0 if kinds[0] == 'view' else None
    vt0 = vtypes.get(0, 'ctx' if kinds[0] == 'ctx' else None)
    out = []

    def offsets(entry):
        """View offsets for a corpus entry: inputs at their header, outputs at SENTINEL."""
        offs = [0] * 4
        for k, vt in vtypes.items():
            output = (k > 0 and not ('recompute_csum' in name and k == 1))
            if output:
                offs[k] = SENTINEL
            else:
                offs[k] = entry['off'].get(vt, L3_OFF.get(entry.get('name'), 14) if vt != 'eth' else 0)
        if name.endswith(('__parse',)) and not name.startswith('bnt_ctx'):
            offs[2] = SENTINEL
        return offs

    def args_default():
        a = [0] * 4
        for k, t in enumerate(params):
            if kinds[k] == 'arg':
                a[k] = default_arg(name, t, k)
        if name.endswith('__parse'):
            a[1] = 14
        return a

    buf = base_buf(name, sig)
    for pname, e in CORPUS.items():
        e = dict(e, name=pname)
        out.append((f'pkt:{pname}', e['data'], io_pack(args_default(), offsets(e), 0, buf)))

    main = CORPUS[MAIN_BY_API.get(name, MAIN.get(vt0, 'v4tcp'))]
    mo = offsets(dict(main, name=MAIN_BY_API.get(name, MAIN.get(vt0))))
    for sweep in (MAIN_BY_API.get(name, MAIN.get(vt0, 'v4tcp')),) + EXTRA_CUTS.get(vt0, ()):
        e = CORPUS[sweep]
        o = offsets(dict(e, name=sweep))
        for n in range(14, len(e['data'])):  # XDP never sees less than an Ethernet header
            out.append((f'cut:{sweep}:{n}', e['data'][:n], io_pack(args_default(), o, 0, buf)))
    for k, kd in enumerate(kinds):
        if kd in ('view', 'ptr'):
            out.append((f'null:{k}', main['data'], io_pack(args_default(), mo, 1 << k, buf)))
        if kd == 'arg':
            for v in arg_values(name, params[k], k):
                a = args_default()
                a[k] = v
                out.append((f'arg{k}:{v:#x}', main['data'], io_pack(a, mo, 0, buf)))
    if in_view is not None:  # views come from parse, which stops at 0xffff (see parseoff)
        for o in (len(main['data']), 0xfffe, 0xffff):
            offs = list(mo)
            offs[0] = o
            out.append((f'off:{o:#x}', main['data'], io_pack(args_default(), offs, 0, buf)))
    if name.endswith('__parse'):
        for o in (0, 0xffff, 0x10000, 0xfffffffe):
            a = args_default()
            a[1] = o
            out.append((f'parseoff:{o:#x}', main['data'], io_pack(a, mo, 0, buf)))
    if name.startswith('bnt_fib'):
        for st in (0, 1, 4, -19):
            b = bytearray(buf)
            b[0:68] = fib_struct(st)
            out.append((f'fibstatus:{st}', main['data'], io_pack(args_default(), mo, 0, b)))
    return out

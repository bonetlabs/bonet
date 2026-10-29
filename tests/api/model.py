"""Reference model of the public XDP API: what each call should return and do.

model(api, sig, pkt, io) takes the packet and the bnt_api_io content before the
call, and returns an Expect: the return value, the io buffers and views after
the call, and the packet after the call. It is written from the protocols and
the API contract, not from the C code, so it disagrees with BONet where BONet
is wrong. Two rules of the contract are applied to every API:
  - an out parameter is cleared before anything can fail (pointer outputs are
    zeroed, views keep the value they had);
  - on error the packet is left as it was. A difference here is reported apart
    from the other failures (see check.py), since some write paths fail late
    by design.
"""
import struct

OK, TRUNC, UNSUPPORTED, BAD_PROTO, FRAGMENT, WRITE, BAD_ARG, BAD_STATE, TOO_DEEP = 0, -1, -2, -3, -4, -5, -6, -7, -8
NAMES = {0: 'OK', -1: 'TRUNC', -2: 'UNSUPPORTED', -3: 'BAD_PROTO', -4: 'FRAGMENT', -5: 'WRITE',
         -6: 'BAD_ARG', -7: 'BAD_STATE', -8: 'TOO_DEEP'}

MAX_VLAN, MAX_EXT, MAX_SEGS = 2, 6, 8
BOUND_L2, BOUND_L3, BOUND_L4 = 0x3f, 0xff, 0x1ff
VLAN_TPIDS = (0x8100, 0x88a8)
IPV6_EXT = (0, 43, 44, 51, 60, 135, 139, 140)
HEADROOM = 256       # BPF_PROG_TEST_RUN's XDP headroom
CSUM_MAX = 1500      # longest range the full recomputes sum

IO = struct.Struct('<4Q4IIi8I384s')
SLOT = 96


class Err(Exception):
    def __init__(self, code):
        self.code = code


def csum16(b):
    """Internet checksum (the value to store) of b."""
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


def csum_update(check, old, new):
    """RFC 1624 eqn. 3: the checksum after the 16-bit words of old become new."""
    s = ~check & 0xffff
    for i in range(0, len(old), 2):
        s += ~int.from_bytes(old[i:i + 2], 'big') & 0xffff
        s += int.from_bytes(new[i:i + 2], 'big')
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


class Pkt:
    def __init__(self, data):
        self.b = bytearray(data)

    def ok(self, off, n):
        return 0 <= off and n <= 0xffff and off + n <= 0xffff and off + n <= len(self.b)

    def rd(self, off, n):
        if not self.ok(off, n):
            raise Err(TRUNC)
        return bytes(self.b[off:off + n])

    def wr(self, off, data):
        if not self.ok(off, len(data)):
            raise Err(TRUNC)
        self.b[off:off + len(data)] = data

    def u8(self, off):
        return self.rd(off, 1)[0]

    def be16(self, off):
        return int.from_bytes(self.rd(off, 2), 'big')

    def be32(self, off):
        return int.from_bytes(self.rd(off, 4), 'big')

    def w8(self, off, v):
        self.wr(off, bytes([v & 0xff]))

    def w16(self, off, v):
        self.wr(off, (v & 0xffff).to_bytes(2, 'big'))

    def w32(self, off, v):
        self.wr(off, (v & 0xffffffff).to_bytes(4, 'big'))


# ---- header walks ----------------------------------------------------

def eth_meta(p, e):
    """(header length, final EtherType, VLAN TCIs) of the Ethernet header at e."""
    proto = p.be16(e + 12)
    hlen, tcis = 14, []
    while proto in VLAN_TPIDS:
        if len(tcis) == MAX_VLAN:
            raise Err(TOO_DEEP)
        tcis.append(p.be16(e + hlen))
        proto = p.be16(e + hlen + 2)
        hlen += 4
    return hlen, proto, tcis


def ipv4_meta(p, o):
    """dict of the IPv4 header at o: hlen, protocol, next_off, frag, l4_valid."""
    h = p.rd(o, 20)
    if h[0] >> 4 != 4:
        raise Err(BAD_PROTO)
    hlen = (h[0] & 15) * 4
    if hlen < 20:
        raise Err(BAD_PROTO)
    p.rd(o, hlen)
    if int.from_bytes(h[2:4], 'big') < hlen:
        raise Err(BAD_PROTO)
    frag = int.from_bytes(h[6:8], 'big')
    return dict(hlen=hlen, protocol=h[9], next_off=o + hlen, is_frag=bool(frag & 0x3fff),
                l4_valid=not frag & 0x1fff)


def ipv6_meta(p, o, whole_ext=False, stop_at_frag=False):
    """dict of the IPv6 header at o and its extension chain. whole_ext: the
    walk also requires each extension header to be inside the packet (the
    ctx__find_* walk), not just the bytes it reads. stop_at_frag: the walk ends
    at the Fragment header (the APIs that only need that header)."""
    p.rd(o, 40 if whole_ext else 8)
    if p.u8(o) >> 4 != 6:
        raise Err(BAD_PROTO)
    nh = p.u8(o + 6)
    m = dict(l4_proto=nh, next_off=o + 40, ext_depth=0, has_frag=False, is_frag=False,
             l4_valid=True, frag_off_flags=0, frag_hdr_off=0)
    cur = o + 40
    while nh in IPV6_EXT:
        if m['ext_depth'] == MAX_EXT:
            raise Err(TOO_DEEP)
        if whole_ext:
            p.rd(cur, 8)
        nxt = p.u8(cur)
        m['ext_depth'] += 1
        if nh == 44:
            fo = p.be16(cur + 2)
            m.update(has_frag=True, frag_hdr_off=cur, frag_off_flags=fo)
            if fo & 0xfff9:
                m['is_frag'] = True
            if stop_at_frag:
                return m
            if fo & 0xfff8:
                m.update(l4_valid=False, l4_proto=nxt, next_off=cur + 8)
                return m
            ln = 8
        elif nh == 51:
            ln = (p.u8(cur + 1) + 2) * 4
        else:
            ln = (p.u8(cur + 1) + 1) * 8
        if whole_ext:
            p.rd(cur, ln)
        nh, cur = nxt, cur + ln
    m.update(l4_proto=nh, next_off=cur)
    return m


def arp_meta(p, a):
    h = p.rd(a, 8)
    hln, pln = h[4], h[5]
    hlen = 8 + 2 * hln + 2 * pln
    p.rd(a, hlen)
    return dict(hlen=hlen, htype=int.from_bytes(h[0:2], 'big'), ptype=int.from_bytes(h[2:4], 'big'),
                hln=hln, pln=pln, eth_ipv4=h[0:6] == b'\x00\x01\x08\x00\x06\x04')


def off_ret(off, bound):
    if off > bound:
        raise Err(TRUNC)
    return off


# ---- arguments -------------------------------------------------------

class Slot:
    """io.buf[k], the memory a pointer argument points to."""
    def __init__(self, buf, k):
        self.buf, self.base = buf, k * SLOT

    def put(self, data):
        self.buf[self.base:self.base + len(data)] = data

    def get(self, n):
        return bytes(self.buf[self.base:self.base + n])


class View:
    def __init__(self, vout, k, off):
        self.vout, self.k, self.off = vout, k, off

    def set(self, off):
        self.off = off
        self.vout[2 * self.k] = off & 0xffffffff


OUT_SIZE = {'__u8 *': 1, '_Bool *': 1, '__u16 *': 2, '__u32 *': 4, '__be32 *': 4,
            'unsigned char *': 6, 'struct in6_addr *': 16, 'bnt_fib4 *': 68, 'bnt_fib6 *': 68}


# ---- the API ---------------------------------------------------------
# Each entry gets (p, *args): views as View or None, pointers as Slot or
# None, scalars as ints. It returns the status, or raises Err.

API = {}


def api(name):
    def reg(f):
        API[name] = f
        return f
    return reg


def need(*xs):
    if any(x is None for x in xs):
        raise Err(BAD_ARG)


def out_clear(out, n):
    if out is None:
        raise Err(BAD_ARG)
    out.put(bytes(n))


MAX_VIEW_OFFSET = 0xffff  # past it, off + field would wrap in 32 bits


# parse: every view type
for _h in ('eth', 'ipv4', 'ipv6', 'tcp', 'udp', 'icmp4', 'icmp6', 'arp'):
    @api(f'bnt_{_h}__parse')
    def _parse(p, ctx, off, v):
        need(v)
        if off > MAX_VIEW_OFFSET:
            return TRUNC
        v.set(off)
        return OK


@api('bnt_mpls__parse')
def _(p, ctx, off, v):
    need(v)
    p.rd(off, 4)
    v.set(off)
    return OK


# plain field getters: (view, field offset, size, transform)
GETTERS = {
    'bnt_ipv4__get_tos': (1, 1, None), 'bnt_ipv4__get_total_len': (2, 2, None),
    'bnt_ipv4__get_id': (4, 2, None), 'bnt_ipv4__get_frag_off': (6, 2, None),
    'bnt_ipv4__get_ttl': (8, 1, None), 'bnt_ipv4__get_protocol': (9, 1, None),
    'bnt_ipv4__get_check': (10, 2, None), 'bnt_ipv4__get_saddr': (12, 4, 'raw'),
    'bnt_ipv4__get_daddr': (16, 4, 'raw'), 'bnt_ipv4__get_version': (0, 1, lambda v: v >> 4),
    'bnt_ipv4__get_ihl': (0, 1, lambda v: v & 15),
    'bnt_ipv4__is_fragment': (6, 2, lambda v: int(bool(v & 0x3fff))),
    'bnt_ipv4__is_reserved_fragment_flag': (6, 2, lambda v: int(bool(v & 0x8000))),
    'bnt_ipv4__is_dont_fragment': (6, 2, lambda v: int(bool(v & 0x4000))),
    'bnt_ipv4__is_more_fragments': (6, 2, lambda v: int(bool(v & 0x2000))),
    'bnt_ipv6__get_version': (0, 1, lambda v: v >> 4),
    'bnt_ipv6__get_traffic_class': (0, 4, lambda v: (v >> 20) & 0xff),
    'bnt_ipv6__get_flow_label': (0, 4, lambda v: v & 0xfffff),
    'bnt_ipv6__get_payload_len': (4, 2, None), 'bnt_ipv6__get_base_nexthdr': (6, 1, None),
    'bnt_ipv6__get_hop_limit': (7, 1, None), 'bnt_ipv6__get_saddr': (8, 16, 'raw'),
    'bnt_ipv6__get_daddr': (24, 16, 'raw'),
    'bnt_tcp__get_sport': (0, 2, None), 'bnt_tcp__get_dport': (2, 2, None),
    'bnt_tcp__get_seq': (4, 4, None), 'bnt_tcp__get_ack_seq': (8, 4, None),
    'bnt_tcp__get_flags': (12, 2, lambda v: v & 0x1ff), 'bnt_tcp__get_window': (14, 2, None),
    'bnt_tcp__get_check': (16, 2, None), 'bnt_tcp__get_urg_ptr': (18, 2, None),
    'bnt_udp__get_sport': (0, 2, None), 'bnt_udp__get_dport': (2, 2, None),
    'bnt_udp__get_len': (4, 2, None), 'bnt_udp__get_check': (6, 2, None),
    'bnt_icmp4__get_type': (0, 1, None), 'bnt_icmp4__get_code': (1, 1, None),
    'bnt_icmp4__get_checksum': (2, 2, None), 'bnt_icmp4__get_echo_id': (4, 2, None),
    'bnt_icmp4__get_echo_seq': (6, 2, None),
    'bnt_icmp6__get_type': (0, 1, None), 'bnt_icmp6__get_code': (1, 1, None),
    'bnt_icmp6__get_checksum': (2, 2, None), 'bnt_icmp6__get_echo_id': (4, 2, None),
    'bnt_icmp6__get_echo_seq': (6, 2, None),
    'bnt_eth__get_dmac': (0, 6, 'raw'), 'bnt_eth__get_smac': (6, 6, 'raw'),
    'bnt_eth__get_outer_ethertype': (12, 2, None),
    'bnt_arp__get_htype': (0, 2, None), 'bnt_arp__get_ptype': (2, 2, None),
    'bnt_arp__get_haddr_len': (4, 1, None), 'bnt_arp__get_paddr_len': (5, 1, None),
    'bnt_arp__get_oper': (6, 2, None),
}
for _f, (_fo, _n, _t) in [(f'bnt_tcp__is_{n}', (12, 2, b)) for n, b in
                          (('fin', 1), ('syn', 2), ('rst', 4), ('psh', 8), ('ack', 16), ('urg', 32),
                           ('ece', 64), ('cwr', 128), ('ns', 256))]:
    GETTERS[_f] = (_fo, _n, (lambda bit: lambda v: int(bool(v & bit)))(_t))
for _f, (_fo, _n, _t) in [(f'bnt_mpls__{n}', (0, 4, t)) for n, t in
                          (('get_label', lambda v: v >> 12), ('get_tc', lambda v: (v >> 9) & 7),
                           ('get_ttl', lambda v: v & 0xff), ('is_bos', lambda v: (v >> 8) & 1))]:
    GETTERS[_f] = (_fo, _n, _t)


def make_getter(fo, n, t, osize):
    def f(p, v, out):
        out_clear(out, osize)
        need(v)
        raw = p.rd(v.off + fo, n)
        if t == 'raw':
            out.put(raw)
        else:
            x = int.from_bytes(raw, 'big')
            out.put(((t(x) if t else x)).to_bytes(osize, 'little'))
        return OK
    return f


# setters without checksum update: (field offset, size, how the value lands)
RAW_SETTERS = {
    'bnt_ipv4__set_check': (10, 2), 'bnt_ipv4__set_tos_no_csum': (1, 1),
    'bnt_ipv4__set_ttl_no_csum': (8, 1), 'bnt_ipv4__set_saddr_no_csum': (12, 'be32raw'),
    'bnt_ipv4__set_daddr_no_csum': (16, 'be32raw'), 'bnt_ipv4__set_id_no_csum': (4, 2),
    'bnt_ipv4__set_total_len_no_csum': (2, 2), 'bnt_ipv4__set_protocol_no_csum': (9, 1),
    'bnt_ipv4__set_frag_off_no_csum': (6, 2),
    'bnt_ipv6__set_hop_limit': (7, 1), 'bnt_ipv6__set_base_nexthdr': (6, 1),
    'bnt_tcp__set_check': (16, 2), 'bnt_tcp__set_sport_no_csum': (0, 2),
    'bnt_tcp__set_dport_no_csum': (2, 2), 'bnt_tcp__set_seq_no_csum': (4, 4),
    'bnt_tcp__set_ack_seq_no_csum': (8, 4), 'bnt_tcp__set_window_no_csum': (14, 2),
    'bnt_tcp__set_urg_ptr_no_csum': (18, 2),
    'bnt_udp__set_check': (6, 2), 'bnt_udp__set_sport_no_csum': (0, 2),
    'bnt_udp__set_dport_no_csum': (2, 2), 'bnt_udp__set_len_no_csum': (4, 2),
    'bnt_icmp4__set_checksum': (2, 2), 'bnt_icmp4__set_type_no_csum': (0, 1),
    'bnt_icmp4__set_code_no_csum': (1, 1), 'bnt_icmp4__set_echo_id_no_csum': (4, 2),
    'bnt_icmp4__set_echo_seq_no_csum': (6, 2), 'bnt_icmp6__set_checksum': (2, 2),
    'bnt_eth__set_outer_ethertype': (12, 2),
    'bnt_arp__set_htype': (0, 2), 'bnt_arp__set_ptype': (2, 2), 'bnt_arp__set_haddr_len': (4, 1),
    'bnt_arp__set_paddr_len': (5, 1), 'bnt_arp__set_oper': (6, 2),
}


def make_raw_setter(fo, n):
    def f(p, v, x):
        need(v)
        if n == 'be32raw':  # a __be32 argument: its bytes go to the packet as they are
            p.wr(v.off + fo, (x & 0xffffffff).to_bytes(4, 'little'))
        else:
            p.wr(v.off + fo, (x & ((1 << 8 * n) - 1)).to_bytes(n, 'big'))
        return OK
    return f


def l4_fix(p, coff, old, new, udp):
    """Update the L4 checksum at coff for old -> new bytes; a zero UDP checksum
    means none and stays zero, and an update never stores zero for UDP."""
    c = p.be16(coff)
    if udp and c == 0:
        return
    c = csum_update(c, old, new)
    if udp and c == 0:
        c = 0xffff
    p.w16(coff, c)


def ipv4_l4_csum_off(p, o):
    """Offset of the TCP/UDP checksum covered by the IPv4 header at o, and whether
    it is UDP, or None (no such checksum, or a non-first fragment)."""
    m = ipv4_meta(p, o)
    if not m['l4_valid'] or m['protocol'] not in (6, 17):
        return None
    return m['next_off'] + (16 if m['protocol'] == 6 else 6), m['protocol'] == 17


def ipv4_set16(fo, mask=None, whole=False):
    """IPv4 setter of the 16-bit word at fo (the field is the masked part) that
    updates the header checksum. whole: the setter needs the 20-byte header."""
    def f(p, v, x):
        need(v)
        o = v.off
        if whole:
            p.rd(o, 20)
        old = p.rd(o + fo, 2)
        p.rd(o + 10, 2)
        w = int.from_bytes(old, 'big')
        nw = (w & ~mask | x & mask) if mask else x & 0xffff
        new = nw.to_bytes(2, 'big')
        p.wr(o + fo, new)
        p.w16(o + 10, csum_update(p.be16(o + 10), old, new))
        return OK
    return f


@api('bnt_ipv4__set_tos')
def _(p, v, x):
    need(v)
    p.rd(v.off, 20)
    return ipv4_set16(0, 0x00ff)(p, v, x & 0xff)


@api('bnt_ipv4__set_ttl')
def _(p, v, x):
    need(v)
    p.rd(v.off, 20)
    return ipv4_set16(8, 0xff00)(p, v, (x & 0xff) << 8)


@api('bnt_ipv4__dec_ttl')
def _(p, v, expired):
    if expired is not None:
        expired.put(b'\0')
    need(v)
    p.rd(v.off, 20)
    ttl = p.u8(v.off + 8)
    if ttl <= 1:
        if expired is not None:
            expired.put(b'\1')
        return BAD_STATE
    return ipv4_set16(8, 0xff00)(p, v, (ttl - 1) << 8)


@api('bnt_ipv4__set_protocol')
def _(p, v, x):
    need(v)
    o = v.off
    p.rd(o, 20)
    before = Pkt(p.b)
    ipv4_set16(8, 0x00ff)(p, v, x & 0xff)
    # the pseudo header of the transport the packet carried changes too
    hlen = (p.u8(o) & 15) * 4
    oldp = before.u8(o + 9)
    if hlen >= 20 and not p.be16(o + 6) & 0x1fff and oldp in (6, 17):
        l4_fix(p, o + hlen + (16 if oldp == 6 else 6), bytes([0, oldp]), bytes([0, x & 0xff]), oldp == 17)
    return OK


@api('bnt_ipv4__set_id')
def _(p, v, x):
    return ipv4_set16(4)(p, v, x)


@api('bnt_ipv4__set_frag_off')
def _(p, v, x):
    return ipv4_set16(6)(p, v, x)


for _n, _bit in (('reserved_fragment_flag', 0x8000), ('dont_fragment', 0x4000), ('more_fragments', 0x2000)):
    API[f'bnt_ipv4__set_{_n}'] = (lambda b: lambda p, v: ipv4_set16(6, b, True)(p, v, b))(_bit)
    API[f'bnt_ipv4__clear_{_n}'] = (lambda b: lambda p, v: ipv4_set16(6, b, True)(p, v, 0))(_bit)


@api('bnt_ipv4__set_total_len')
def _(p, v, x):
    need(v)
    m = ipv4_meta(p, v.off)
    if m['is_frag'] and m['protocol'] in (6, 17):
        return FRAGMENT
    old = p.rd(v.off + 2, 2)
    new = (x & 0xffff).to_bytes(2, 'big')
    ipv4_set16(2)(p, v, x)
    # The pseudo header holds the L4 length, total_len - hlen. For UDP the
    # length field is in the checksum too; udp__set_len updates that copy.
    c = ipv4_l4_csum_off(p, v.off)
    if c:
        l4_fix(p, c[0], old, new, c[1])
    return OK


def ipv4_set_addr(fo):
    def f(p, v, x):
        need(v)
        o = v.off
        p.rd(o, 20)
        old = p.rd(o + fo, 4)
        new = (x & 0xffffffff).to_bytes(4, 'little')
        p.wr(o + fo, new)
        p.w16(o + 10, csum_update(p.be16(o + 10), old, new))
        hlen = (p.u8(o) & 15) * 4
        proto = p.u8(o + 9)
        if hlen >= 20 and not p.be16(o + 6) & 0x1fff and proto in (6, 17):
            l4_fix(p, o + hlen + (16 if proto == 6 else 6), old, new, proto == 17)
        return OK
    return f


API['bnt_ipv4__set_saddr'] = ipv4_set_addr(12)
API['bnt_ipv4__set_daddr'] = ipv4_set_addr(16)


def ipv4_hlen_check(p, o, hlen):
    if hlen < 20 or hlen > 60 or hlen & 3:
        raise Err(BAD_ARG)
    p.rd(o, hlen)


@api('bnt_ipv4__set_hlen')
def _(p, v, x):
    need(v)
    ipv4_hlen_check(p, v.off, x)
    return ipv4_set16(0, 0x0f00)(p, v, (x // 4) << 8)


@api('bnt_ipv4__set_hlen_no_csum')
def _(p, v, x):
    need(v)
    ipv4_hlen_check(p, v.off, x)
    p.w8(v.off, p.u8(v.off) & 0xf0 | x // 4)
    return OK


@api('bnt_ipv4__get_hlen')
def _(p, v, out):
    out_clear(out, 4)
    need(v)
    b = p.u8(v.off)
    if b >> 4 != 4 or (b & 15) < 5:
        return BAD_PROTO
    out.put(((b & 15) * 4).to_bytes(4, 'little'))
    return OK


@api('bnt_ipv4__next_off')
def _(p, v, out):
    out_clear(out, 4)
    need(v)
    m = ipv4_meta(p, v.off)
    if not m['l4_valid']:
        return FRAGMENT
    out.put(off_ret(m['next_off'], BOUND_L3).to_bytes(4, 'little'))
    return OK


@api('bnt_ipv4__next_proto_off')
def _(p, v, proto, out):
    if proto is not None:
        proto.put(b'\0')
    if out is not None:
        out.put(bytes(4))
    need(proto, out, v)
    m = ipv4_meta(p, v.off)
    if not m['l4_valid']:
        return FRAGMENT
    off = off_ret(m['next_off'], BOUND_L3)
    proto.put(bytes([m['protocol']]))
    out.put(off.to_bytes(4, 'little'))
    return OK


@api('bnt_ipv4__recompute_csum')
def _(p, v):
    need(v)
    h = p.rd(v.off, 20)
    if h[0] & 15 != 5:
        return UNSUPPORTED
    p.w16(v.off + 10, csum16(h[:10] + b'\0\0' + h[12:]))
    return OK


def l4_full(p, l4, pseudo, length, coff, udp):
    """Recompute the L4 checksum over length bytes at l4."""
    if length > CSUM_MAX:
        raise Err(TRUNC)
    body = bytearray(p.rd(l4, length))
    p.rd(coff, 2)
    body[coff - l4:coff - l4 + 2] = b'\0\0'
    c = csum16(pseudo + bytes(body))
    if udp and c == 0:
        c = 0xffff
    p.w16(coff, c)


@api('bnt_tcp__recompute_csum4')
def _(p, t, ip):
    need(t, ip)
    vihl = p.u8(ip.off)
    tot = p.be16(ip.off + 2)
    length = (tot - (vihl & 15) * 4) & 0xffff
    p.w16(t.off + 16, 0)
    pseudo = p.rd(ip.off + 12, 8) + bytes([0, 6]) + length.to_bytes(2, 'big')
    l4_full(p, t.off, pseudo, length, t.off + 16, False)
    return OK


@api('bnt_udp__recompute_csum4')
def _(p, u, ip):
    need(u, ip)
    length = p.be16(u.off + 4)
    p.w16(u.off + 6, 0)
    pseudo = p.rd(ip.off + 12, 8) + bytes([0, 17]) + length.to_bytes(2, 'big')
    l4_full(p, u.off, pseudo, length, u.off + 6, True)
    return OK


@api('bnt_icmp4__recompute_csum')
def _(p, ic, length):
    need(ic)
    p.rd(ic.off + 2, 2)
    l4_full(p, ic.off, b'', length & 0xffff, ic.off + 2, False)
    return OK


# ---- IPv6 ------------------------------------------------------------

def ipv6_getter_meta(key, fn=None, check=None):
    def f(p, v, out):
        n = {'l4_proto': 1, 'ext_depth': 1, 'has_frag': 1, 'is_frag': 1, 'frag_off_flags': 2}[key]
        out_clear(out, n)
        need(v)
        m = ipv6_meta(p, v.off, stop_at_frag=key in ('has_frag', 'is_frag', 'frag_off_flags'))
        if check:
            r = check(m)
            if r:
                return r
        val = int(m[key]) if fn is None else fn(m)
        out.put(val.to_bytes(n, 'little'))
        return OK
    return f


API['bnt_ipv6__get_l4_proto'] = ipv6_getter_meta('l4_proto', check=lambda m: None if m['l4_valid'] else FRAGMENT)
API['bnt_ipv6__get_ext_depth'] = ipv6_getter_meta('ext_depth')
API['bnt_ipv6__has_fragment_header'] = ipv6_getter_meta('has_frag')
API['bnt_ipv6__is_fragment'] = ipv6_getter_meta('is_frag')
API['bnt_ipv6__get_fragment_off_flags'] = ipv6_getter_meta(
    'frag_off_flags', check=lambda m: None if m['has_frag'] else BAD_PROTO)


@api('bnt_ipv6__is_more_fragments')
def _(p, v, out):
    out_clear(out, 1)
    need(v)
    m = ipv6_meta(p, v.off, stop_at_frag=True)
    if not m['has_frag']:
        return BAD_PROTO
    out.put(bytes([m['frag_off_flags'] & 1]))
    return OK


def ipv6_frag_write(value_fn):
    def f(p, v):
        need(v)
        m = ipv6_meta(p, v.off, stop_at_frag=True)
        if not m['has_frag']:
            return BAD_PROTO
        p.w16(m['frag_hdr_off'] + 2, value_fn(m['frag_off_flags']))
        return OK
    return f


API['bnt_ipv6__set_more_fragments'] = ipv6_frag_write(lambda w: w | 1)
API['bnt_ipv6__clear_more_fragments'] = ipv6_frag_write(lambda w: w & ~1)


@api('bnt_ipv6__next_off')
def _(p, v, out):
    out_clear(out, 4)
    need(v)
    m = ipv6_meta(p, v.off)
    if not m['l4_valid']:
        return FRAGMENT
    out.put(off_ret(m['next_off'], BOUND_L4).to_bytes(4, 'little'))
    return OK


@api('bnt_ipv6__dec_hop_limit')
def _(p, v, expired):
    if expired is not None:
        expired.put(b'\0')
    need(v)
    p.rd(v.off, 40)
    hl = p.u8(v.off + 7)
    if hl <= 1:
        if expired is not None:
            expired.put(b'\1')
        return BAD_STATE
    p.w8(v.off + 7, hl - 1)
    return OK


def ipv6_l4_csum(m):
    """(checksum offset, is UDP) of the transport covered by IPv6 meta m, or None."""
    if not m['l4_valid'] or m['l4_proto'] not in (6, 17, 58):
        return None
    return m['next_off'] + {6: 16, 17: 6, 58: 2}[m['l4_proto']], m['l4_proto'] == 17


def ipv6_set_addr(fo):
    def f(p, v, addr):
        need(v, addr)
        new = addr.get(16)
        p.rd(v.off, 40)
        old = p.rd(v.off + fo, 16)
        p.wr(v.off + fo, new)
        if p.u8(v.off + 6) in IPV6_EXT:
            m = ipv6_meta(p, v.off)
        else:  # like the raw setters, no version check when there is no chain to walk
            m = dict(l4_valid=True, l4_proto=p.u8(v.off + 6), next_off=v.off + 40)
        c = ipv6_l4_csum(m)
        if c:
            l4_fix(p, c[0], old, new, c[1])
        return OK
    return f


API['bnt_ipv6__set_saddr'] = ipv6_set_addr(8)
API['bnt_ipv6__set_daddr'] = ipv6_set_addr(24)


@api('bnt_ipv6__set_traffic_class')
def _(p, v, x):
    need(v)
    w = p.be32(v.off)
    p.w32(v.off, w & 0xf00fffff | (x & 0xff) << 20)
    return OK


@api('bnt_ipv6__set_flow_label')
def _(p, v, x):
    need(v)
    w = p.be32(v.off)
    p.w32(v.off, w & 0xfff00000 | x & 0xfffff)
    return OK


@api('bnt_ipv6__set_payload_len')
def _(p, v, x):
    need(v)
    m = ipv6_meta(p, v.off)
    if m['is_frag'] and (m['l4_proto'] in (6, 17, 58) or (not m['l4_valid'] and m['l4_proto'] in IPV6_EXT)):
        return FRAGMENT
    old = p.rd(v.off + 4, 2)
    new = (x & 0xffff).to_bytes(2, 'big')
    p.wr(v.off + 4, new)
    # as for IPv4 total_len: the pseudo header's copy of the L4 length
    c = ipv6_l4_csum(m)
    if c:
        l4_fix(p, c[0], old, new, c[1])
    return OK


# ---- TCP / UDP / ICMP setters with checksum --------------------------

def l4_set(fo, n, coff, udp=False, mask=None, word=None):
    """Setter of n bytes at fo that keeps the L4 checksum at coff right. With
    mask, only the masked bits of the 16-bit word at fo change."""
    def f(p, v, x):
        need(v)
        o = v.off
        old = p.rd(o + fo, n)
        if mask is not None:
            w = int.from_bytes(old, 'big')
            new = (w & ~mask | x & mask).to_bytes(n, 'big')
        else:
            new = (x & ((1 << 8 * n) - 1)).to_bytes(n, 'big')
        p.rd(o, word or n)
        p.wr(o + fo, new)
        l4_fix(p, o + coff, old, new, udp)
        return OK
    return f


API['bnt_tcp__set_sport'] = l4_set(0, 2, 16, word=20)
API['bnt_tcp__set_dport'] = l4_set(2, 2, 16, word=20)
API['bnt_tcp__set_seq'] = l4_set(4, 4, 16, word=20)
API['bnt_tcp__set_ack_seq'] = l4_set(8, 4, 16, word=20)
API['bnt_tcp__set_window'] = l4_set(14, 2, 16)
API['bnt_tcp__set_urg_ptr'] = l4_set(18, 2, 16)
API['bnt_tcp__set_flags'] = l4_set(12, 2, 16, mask=0x01ff)
API['bnt_udp__set_sport'] = l4_set(0, 2, 6, udp=True, word=8)
API['bnt_udp__set_dport'] = l4_set(2, 2, 6, udp=True, word=8)
API['bnt_udp__set_len'] = l4_set(4, 2, 6, udp=True)
for _n, _bit in (('fin', 1), ('syn', 2), ('rst', 4), ('psh', 8), ('ack', 16), ('urg', 32), ('ece', 64),
                 ('cwr', 128), ('ns', 256)):
    API[f'bnt_tcp__set_{_n}'] = (lambda b: lambda p, v: l4_set(12, 2, 16, mask=b, word=20)(p, v, b))(_bit)
    API[f'bnt_tcp__clear_{_n}'] = (lambda b: lambda p, v: l4_set(12, 2, 16, mask=b, word=20)(p, v, 0))(_bit)


@api('bnt_tcp__set_flags_no_csum')
def _(p, v, x):
    need(v)
    w = p.be16(v.off + 12)
    p.w16(v.off + 12, w & 0xfe00 | x & 0x1ff)
    return OK


def tcp_doff(csum):
    def f(p, v, x):
        need(v)
        if x < 5 or x > 15:
            return BAD_ARG
        p.rd(v.off, x * 4)
        if csum:
            return l4_set(12, 2, 16, mask=0xf000)(p, v, x << 12)
        w = p.be16(v.off + 12)
        p.w16(v.off + 12, w & 0x0fff | x << 12)
        return OK
    return f


API['bnt_tcp__set_doff'] = tcp_doff(True)
API['bnt_tcp__set_doff_no_csum'] = tcp_doff(False)


def tcp_hlen(p, v):
    hlen = (p.u8(v.off + 12) >> 4) * 4
    if hlen < 20:
        raise Err(BAD_PROTO)
    p.rd(v.off, hlen)
    return hlen


@api('bnt_tcp__get_doff')
def _(p, v, out):
    out_clear(out, 4)
    need(v)
    out.put((tcp_hlen(p, v) // 4).to_bytes(4, 'little'))
    return OK


@api('bnt_tcp__next_off')
def _(p, v, out):
    out_clear(out, 4)
    need(v)
    out.put(off_ret(v.off + tcp_hlen(p, v), BOUND_L4).to_bytes(4, 'little'))
    return OK


for _h, _len, _b in (('udp', 8, BOUND_L4), ('icmp4', 8, BOUND_L4), ('icmp6', 8, BOUND_L4)):
    @api(f'bnt_{_h}__next_off')
    def _(p, v, out, _len=_len, _b=_b):
        out_clear(out, 4)
        need(v)
        out.put(off_ret(v.off + _len, _b).to_bytes(4, 'little'))
        return OK


@api('bnt_mpls__next_off')
def _(p, v, out):
    out_clear(out, 4)
    need(v)
    out.put(off_ret(v.off + 4, BOUND_L3).to_bytes(4, 'little'))
    return OK


def icmp_set(fo, n, kind):
    """ICMPv4/v6 setters: type/code/echo id/echo seq, with checksum."""
    def f(p, v, x):
        need(v)
        o = v.off
        p.rd(o, 8)
        if kind == 'type':
            return l4_set(0, 2, 2, mask=0xff00)(p, v, (x & 0xff) << 8)
        if kind == 'code':
            return l4_set(0, 2, 2, mask=0x00ff)(p, v, x & 0xff)
        return l4_set(fo, 2, 2)(p, v, x)
    return f


for _h in ('icmp4', 'icmp6'):
    API[f'bnt_{_h}__set_type'] = icmp_set(0, 1, 'type')
    API[f'bnt_{_h}__set_code'] = icmp_set(1, 1, 'code')
    API[f'bnt_{_h}__set_echo_id'] = icmp_set(4, 2, 'echo')
    API[f'bnt_{_h}__set_echo_seq'] = icmp_set(6, 2, 'echo')


def icmp6_flags(kind):
    """kind 134 (router advert, flags in byte 5) or 136 (neighbor advert, byte 4)."""
    return 5 if kind == 134 else 4


def icmp6_get_flags(kind):
    def f(p, v, out):
        out_clear(out, 1)
        need(v)
        if p.u8(v.off) != kind:
            return BAD_PROTO
        out.put(bytes([p.u8(v.off + icmp6_flags(kind))]))
        return OK
    return f


API['bnt_icmp6__get_router_advert_flags'] = icmp6_get_flags(134)
API['bnt_icmp6__get_neighbor_advert_flags'] = icmp6_get_flags(136)


@api('bnt_icmp6__get_router_advert_preference')
def _(p, v, out):
    out_clear(out, 1)
    need(v)
    if p.u8(v.off) != 134:
        return BAD_PROTO
    out.put(bytes([(p.u8(v.off + 5) & 0x18) >> 3]))
    return OK


def icmp6_flag(kind, bit, enable, test=False):
    def f(p, v, out=None):
        if test:
            out_clear(out, 1)
        need(v)
        if test:
            if p.u8(v.off) != kind:
                return BAD_PROTO
            out.put(bytes([int(bool(p.u8(v.off + icmp6_flags(kind)) & bit))]))
            return OK
        p.rd(v.off, 8)
        if p.u8(v.off) != kind:
            return BAD_PROTO
        mask = bit if kind == 134 else bit << 8
        return l4_set(4, 2, 2, mask=mask)(p, v, mask if enable else 0)
    return f


for _k, _pre, _flags in ((134, 'router_advert', (('managed', 0x80), ('other', 0x40), ('home_agent', 0x20),
                                                  ('proxy', 0x04))),
                         (136, 'neighbor_advert', (('router', 0x80), ('solicited', 0x40), ('override', 0x20)))):
    for _n, _bit in _flags:
        API[f'bnt_icmp6__set_{_pre}_{_n}'] = icmp6_flag(_k, _bit, True)
        API[f'bnt_icmp6__clear_{_pre}_{_n}'] = icmp6_flag(_k, _bit, False)
        API[f'bnt_icmp6__is_{_pre}_{_n}'] = icmp6_flag(_k, _bit, None, test=True)


@api('bnt_icmp6__set_router_advert_preference')
def _(p, v, pref):
    if pref > 3:
        return BAD_ARG
    need(v)
    if p.u8(v.off) != 134:
        return BAD_PROTO
    p.rd(v.off + 5, 1)
    return l4_set(4, 2, 2, mask=0x18)(p, v, (pref & 3) << 3)


# ---- Ethernet --------------------------------------------------------

@api('bnt_eth__next_off')
def _(p, v, out):
    out_clear(out, 4)
    need(v)
    hlen, _, _ = eth_meta(p, v.off)
    out.put(off_ret(v.off + hlen, BOUND_L2).to_bytes(4, 'little'))
    return OK


def eth_meta_getter(fn, n):
    def f(p, v, out):
        out_clear(out, n)
        need(v)
        out.put(fn(eth_meta(p, v.off)).to_bytes(n, 'little'))
        return OK
    return f


API['bnt_eth__get_ethertype'] = eth_meta_getter(lambda m: m[1], 2)
API['bnt_eth__get_vlan_depth'] = eth_meta_getter(lambda m: len(m[2]), 1)


def vlan_tci(p, v, idx):
    need(v)
    _, _, tcis = eth_meta(p, v.off)
    if idx >= len(tcis):
        raise Err(BAD_ARG)
    return tcis[idx]


@api('bnt_eth__get_vlan_tci')
def _(p, v, idx, out):
    out_clear(out, 2)
    out.put(vlan_tci(p, v, idx).to_bytes(2, 'little'))
    return OK


@api('bnt_eth__is_vlan_drop_eligible')
def _(p, v, idx, out):
    out_clear(out, 1)
    out.put(bytes([int(bool(vlan_tci(p, v, idx) & 0x1000))]))
    return OK


@api('bnt_eth__set_vlan_tci')
def _(p, v, idx, tci):
    vlan_tci(p, v, idx)
    p.w16(v.off + 14 + 4 * idx, tci)
    return OK


for _n, _en in (('set', True), ('clear', False)):
    @api(f'bnt_eth__{_n}_vlan_drop_eligible')
    def _(p, v, idx, _en=_en):
        t = vlan_tci(p, v, idx)
        p.w16(v.off + 14 + 4 * idx, t | 0x1000 if _en else t & ~0x1000)
        return OK


@api('bnt_eth__set_ethertype')
def _(p, v, x):
    need(v)
    hlen, _, _ = eth_meta(p, v.off)
    p.w16(v.off + hlen - 2, x)
    return OK


for _n, _fo in (('dmac', 0), ('smac', 6)):
    @api(f'bnt_eth__set_{_n}')
    def _(p, v, mac, _fo=_fo):
        need(v, mac)
        p.wr(v.off + _fo, mac.get(6))
        return OK


def eth_next(protos, parse):
    def f(p, v, out):
        need(out, v)
        hlen, proto, _ = eth_meta(p, v.off)
        if proto not in protos:
            return BAD_PROTO
        if parse == 'mpls':
            p.rd(v.off + hlen, 4)
        out.set(v.off + hlen)
        return OK
    return f


API['bnt_eth__next_ipv4'] = eth_next((0x0800,), None)
API['bnt_eth__next_ipv6'] = eth_next((0x86dd,), None)
API['bnt_eth__next_arp'] = eth_next((0x0806,), None)
API['bnt_eth__next_mpls'] = eth_next((0x8847, 0x8848), 'mpls')


@api('bnt_eth__parse_l3')
def _(p, v, ip4, ip6):
    need(v)
    hlen, proto, _ = eth_meta(p, v.off)
    if proto == 0x0800:
        need(ip4)
        ip4.set(v.off + hlen)
        return OK
    if proto == 0x86dd:
        need(ip6)
        ip6.set(v.off + hlen)
        return OK
    return BAD_PROTO if proto == 0x0806 else UNSUPPORTED


# ---- next header from IPv4 / IPv6 ------------------------------------

def ip_next(v6, proto):
    def f(p, v, out):
        need(out, v)
        m = ipv6_meta(p, v.off) if v6 else ipv4_meta(p, v.off)
        if not m['l4_valid']:
            return FRAGMENT
        if m['l4_proto' if v6 else 'protocol'] != proto:
            return BAD_PROTO
        out.set(m['next_off'])
        return OK
    return f


for _v6, _src in ((False, 'ipv4'), (True, 'ipv6')):
    for _dst, _proto in (('ipv4', 4), ('ipv6', 41), ('tcp', 6), ('udp', 17)):
        API[f'bnt_{_src}__next_{_dst}'] = ip_next(_v6, _proto)
API['bnt_ipv4__next_icmp4'] = ip_next(False, 1)
API['bnt_ipv6__next_icmp6'] = ip_next(True, 58)


def parse_l4(v6):
    def f(p, v, tcp, udp, icmp):
        need(v)
        m = ipv6_meta(p, v.off) if v6 else ipv4_meta(p, v.off)
        if not m['l4_valid']:
            return FRAGMENT
        out = {6: tcp, 17: udp, (58 if v6 else 1): icmp}.get(m['l4_proto' if v6 else 'protocol'], False)
        if out is False:
            return UNSUPPORTED
        need(out)
        out.set(m['next_off'])
        return OK
    return f


API['bnt_ipv4__parse_l4'] = parse_l4(False)
API['bnt_ipv6__parse_l4'] = parse_l4(True)


# ---- MPLS ------------------------------------------------------------

def mpls_set(fn):
    def f(p, v, x):
        need(v)
        r = fn(p.be32(v.off), x)
        if r is None:
            return BAD_ARG
        p.w32(v.off, r)
        return OK
    return f


@api('bnt_mpls__set_label')
def _(p, v, x):
    if x > 0xfffff:
        return BAD_ARG
    return mpls_set(lambda w, x: w & 0xfff | x << 12)(p, v, x)


API['bnt_mpls__set_tc'] = mpls_set(lambda w, x: w & ~0xe00 | (x & 7) << 9)
API['bnt_mpls__set_ttl'] = mpls_set(lambda w, x: w & ~0xff | x & 0xff)
API['bnt_mpls__set_bos'] = mpls_set(lambda w, x: w | 0x100 if x else w & ~0x100)


def mpls_next(kind):
    def f(p, v, out):
        need(v, out)
        bos = p.be32(v.off) >> 8 & 1
        off = v.off + 4
        if kind == 'mpls':
            if bos:
                return BAD_PROTO
            p.rd(off, 4)
        else:
            if not bos or p.u8(off) >> 4 != kind:
                return BAD_PROTO
        out.set(off)
        return OK
    return f


API['bnt_mpls__next_mpls'] = mpls_next('mpls')
API['bnt_mpls__next_ipv4'] = mpls_next(4)
API['bnt_mpls__next_ipv6'] = mpls_next(6)


# ---- ARP -------------------------------------------------------------

@api('bnt_arp__next_off')
def _(p, v, out):
    out_clear(out, 4)
    need(v)
    out.put(off_ret(v.off + arp_meta(p, v.off)['hlen'], BOUND_L3).to_bytes(4, 'little'))
    return OK


@api('bnt_arp__is_eth_ipv4')
def _(p, v, out):
    out_clear(out, 1)
    need(v)
    out.put(bytes([int(arp_meta(p, v.off)['eth_ipv4'])]))
    return OK


ARP_ADDR = {'sha': (8, 6), 'spa': (14, 4), 'tha': (18, 6), 'tpa': (24, 4)}
for _n, (_fo, _len) in ARP_ADDR.items():
    @api(f'bnt_arp__get_{_n}')
    def _(p, v, out, _fo=_fo, _len=_len):
        out_clear(out, _len)
        need(v)
        if not arp_meta(p, v.off)['eth_ipv4']:
            return UNSUPPORTED
        out.put(p.rd(v.off + _fo, _len))
        return OK

    @api(f'bnt_arp__set_{_n}')
    def _(p, v, x, _fo=_fo, _len=_len):
        if _len == 6:
            need(v, x)
        else:
            need(v)
        if not arp_meta(p, v.off)['eth_ipv4']:
            return UNSUPPORTED
        p.wr(v.off + _fo, x.get(6) if _len == 6 else (x & 0xffffffff).to_bytes(4, 'little'))
        return OK


# ---- FIB -------------------------------------------------------------
# bpf_fib_lookup's result depends on the machine's routes: the model fills the
# parameters BONet sets, and check.py compares only those (FIB_FIELDS).

FIB_FIELDS = {4: [(0, 2), (6, 2), (12, 1), (16, 4), (32, 4)], 6: [(0, 2), (6, 2), (12, 4), (16, 16), (32, 16)]}


@api('bnt_ipv4__fib_lookup')
def _(p, v, fib):
    need(v, fib)
    fib.put(bytes(68))
    o = v.off
    h = p.rd(o, 20)
    tot = int.from_bytes(h[2:4], 'big')
    f = bytearray(68)
    f[0], f[1] = 2, h[9]
    f[6:8] = tot.to_bytes(2, 'little')
    f[12] = h[1]
    f[16:20], f[32:36] = h[12:16], h[16:20]
    fib.put(bytes(f))
    return OK


@api('bnt_ipv6__fib_lookup')
def _(p, v, fib):
    need(v, fib)
    fib.put(bytes(68))
    h = p.rd(v.off, 40)
    f = bytearray(68)
    f[0], f[1] = 10, h[6]
    f[6:8] = ((int.from_bytes(h[4:6], 'big') + 40) & 0xffff).to_bytes(2, 'little')
    f[12:16] = (int.from_bytes(h[0:4], 'big') & 0x0fffffff).to_bytes(4, 'big')
    f[16:32], f[32:48] = h[8:24], h[24:40]
    fib.put(bytes(f))
    return OK


for _v in ('4', '6'):
    API[f'bnt_fib{_v}__get_status'] = lambda p, fib: BAD_ARG if fib is None else int.from_bytes(
        fib.get(68)[64:68], 'little', signed=True)
    API[f'bnt_fib{_v}__get_out_ifindex'] = lambda p, fib: 0 if fib is None else int.from_bytes(
        fib.get(12)[8:12], 'little', signed=True)
    API[f'bnt_fib{_v}__is_success'] = lambda p, fib: int(fib is not None and fib.get(68)[64:68] == bytes(4))


def fib_mac(fo):
    def f(p, fib, out):  # out is io.buf[1], where the program copies the MAC
        if fib is None:
            return 0
        out.put(fib.get(64)[fo:fo + 6])
        return 1
    return f


for _v in ('4', '6'):
    API[f'bnt_fib{_v}__get_smac'] = fib_mac(52)
    API[f'bnt_fib{_v}__get_dmac'] = fib_mac(58)


# ---- ctx__find_* -----------------------------------------------------

def l3_mismatch(proto):
    return BAD_PROTO if proto in (0x0800, 0x86dd, 0x0806, 0x8847, 0x8848) else UNSUPPORTED


def find(kind):
    def f(p, ctx, out):
        need(out)
        hlen, proto, _ = eth_meta(p, 0)
        if kind == 'ipv4':
            if proto != 0x0800:
                return l3_mismatch(proto)
            ipv4_meta(p, hlen)
            off = hlen
        elif kind == 'ipv6':
            if proto != 0x86dd:
                return l3_mismatch(proto)
            p.rd(hlen, 40)
            if p.u8(hlen) >> 4 != 6:
                return BAD_PROTO
            off = hlen
        elif kind == 'arp':
            if proto != 0x0806:
                return l3_mismatch(proto)
            m = arp_meta(p, hlen)
            off_ret(hlen + m['hlen'], BOUND_L3)
            off = hlen
        elif kind == 'mpls':
            if proto not in (0x8847, 0x8848):
                return l3_mismatch(proto)
            p.rd(hlen, 4)
            off = hlen
        else:
            want4, want6 = {'tcp': (6, 6), 'udp': (17, 17), 'icmp4': (1, None), 'icmp6': (None, 58)}[kind]
            if proto == 0x0800 and want4 is not None:
                m = ipv4_meta(p, hlen)
                if not m['l4_valid']:
                    return FRAGMENT
                if m['protocol'] != want4:
                    return BAD_PROTO if m['protocol'] in (6, 17, 1) else UNSUPPORTED
            elif proto == 0x86dd and want6 is not None:
                m = ipv6_meta(p, hlen, whole_ext=True)
                if not m['l4_valid']:
                    return FRAGMENT
                if m['l4_proto'] != want6:
                    return BAD_PROTO if m['l4_proto'] in (6, 17, 58) else UNSUPPORTED
            else:
                return l3_mismatch(proto)
            off = m['next_off']
        out.set(off)
        return OK
    return f


for _k in ('ipv4', 'ipv6', 'arp', 'mpls', 'tcp', 'udp', 'icmp4', 'icmp6'):
    API[f'bnt_ctx__find_{_k}'] = find(_k)


# ---- insert / remove -------------------------------------------------
# The packet grows or shrinks at the front (bpf_xdp_adjust_head). The headers
# in front of the insertion point move; everything else stays where it is.

def walk_vlans(p, e):
    proto = p.be16(e + 12)
    hlen = 14
    for _ in range(MAX_VLAN):
        if proto not in VLAN_TPIDS:
            break
        proto = p.be16(e + hlen + 2)
        hlen += 4
    if proto in VLAN_TPIDS:
        raise Err(TOO_DEEP)
    return hlen, proto


def insert(p, at, data, prefix=None, block=False):
    """block: the moved prefix is always copied as a 64-byte block (the SRH
    insert)."""
    pre = at if prefix is None else prefix
    if pre > 64:
        raise Err(TOO_DEEP)
    # only an Ethernet header at offset 0 (a 14-byte prefix) is moved without
    # the 64-byte window
    if len(p.b) < (pre if pre == 14 and not block else 64):
        raise Err(TRUNC)
    if len(data) > HEADROOM:
        raise Err(WRITE)
    p.b[at:at] = data


def remove(p, at, n, prefix=None):
    if (at if prefix is None else prefix) > 64:
        raise Err(TOO_DEEP)
    if len(p.b) < 64 + n:
        raise Err(TRUNC)
    del p.b[at:at + n]


@api('bnt_eth__insert_vlan')
def _(p, v, tpid, tci):
    need(v)
    e = v.off
    outer = p.be16(e + 12)
    proto, depth = outer, 0
    while proto in VLAN_TPIDS and depth < MAX_VLAN:
        proto = p.be16(e + 14 + 4 * depth + 2)
        depth += 1
    if depth >= MAX_VLAN:
        return TOO_DEEP
    insert(p, e + 12, (tpid & 0xffff).to_bytes(2, 'big') + (tci & 0xffff).to_bytes(2, 'big'), e + 14)
    return OK


@api('bnt_eth__remove_vlan')
def _(p, v):
    need(v)
    e = v.off
    if p.be16(e + 12) not in VLAN_TPIDS:
        return BAD_PROTO
    p.rd(e + 16, 2)
    remove(p, e + 12, 4, e + 14)
    return OK


@api('bnt_eth__insert_mpls')
def _(p, v, label, tc, ttl):
    need(v)
    if label > 0xfffff:
        return BAD_ARG
    hlen, proto = walk_vlans(p, v.off)
    bos = proto not in (0x8847, 0x8848)
    lse = label << 12 | (tc & 7) << 9 | bos << 8 | ttl & 0xff
    at = v.off + hlen
    insert(p, at, lse.to_bytes(4, 'big'))
    p.w16(at - 2, 0x8847)
    return OK


@api('bnt_eth__insert_ipv4')
def _(p, v, proto, saddr, daddr):
    need(v)
    hlen, _ = walk_vlans(p, v.off)
    at = v.off + hlen
    total = len(p.b) - at + 20
    h = bytearray(20)
    h[0], h[2:4], h[6:8], h[8], h[9] = 0x45, (total & 0xffff).to_bytes(2, 'big'), b'\x40\x00', 64, proto & 0xff
    h[12:16], h[16:20] = (saddr & 0xffffffff).to_bytes(4, 'little'), (daddr & 0xffffffff).to_bytes(4, 'little')
    h[10:12] = csum16(bytes(h)).to_bytes(2, 'big')
    insert(p, at, bytes(h))
    if total > 0xffff:
        raise Err(TRUNC)
    p.w16(at - 2, 0x0800)
    return OK


@api('bnt_eth__insert_ipv6')
def _(p, v, nh, saddr, daddr):
    need(v, saddr, daddr)
    hlen, _ = walk_vlans(p, v.off)
    at = v.off + hlen
    plen = len(p.b) - at
    h = bytearray(40)
    h[0], h[4:6], h[6], h[7] = 0x60, (plen & 0xffff).to_bytes(2, 'big'), nh & 0xff, 64
    h[8:24], h[24:40] = saddr.get(16), daddr.get(16)
    insert(p, at, bytes(h))
    if plen > 0xffff:
        raise Err(TRUNC)
    p.w16(at - 2, 0x86dd)
    return OK


def eth_remove_ip(v6):
    def f(p, v):
        need(v)
        hlen, proto = walk_vlans(p, v.off)
        if proto != (0x86dd if v6 else 0x0800):
            return BAD_PROTO
        at = v.off + hlen
        h = p.rd(at, 40 if v6 else 20)
        inner = h[6] if v6 else h[9]
        if (h[0] >> 4 != 6) if v6 else h[0] != 0x45:
            return UNSUPPORTED
        if inner not in (4, 41):
            return UNSUPPORTED
        p.w16(at - 2, 0x0800 if inner == 4 else 0x86dd)
        remove(p, at, 40 if v6 else 20)
        return OK
    return f


API['bnt_eth__remove_ipv4'] = eth_remove_ip(False)
API['bnt_eth__remove_ipv6'] = eth_remove_ip(True)


@api('bnt_ipv6__insert_srh')
def _(p, v, segs, n):
    need(v, segs)
    if not n or n > MAX_SEGS:
        return BAD_ARG
    o = v.off
    h = p.rd(o, 40)
    if h[0] >> 4 != 6:
        return BAD_PROTO
    size = 8 + 16 * n
    plen = int.from_bytes(h[4:6], 'big')
    if plen + size > 0xffff:
        return TRUNC
    seglist = segs.get(16 * MAX_SEGS)
    srh = bytes([h[6], 2 * n, 4, n - 1, n - 1, 0, 0, 0])
    srh += b''.join(seglist[16 * (n - 1 - i):16 * (n - i)] for i in range(n))  # reversed
    insert(p, o + 40, srh, block=True)
    p.w8(o + 6, 43)
    p.w16(o + 4, plen + size)
    return OK


for _f, (_fo, _n) in RAW_SETTERS.items():
    API[_f] = make_raw_setter(_fo, _n)


# ---- running the model -----------------------------------------------

class Expect:
    def __init__(self, ret, io, pkt, slots, error_pkt_free):
        self.ret, self.io, self.pkt, self.slots = ret, io, pkt, slots
        self.error_pkt_free = error_pkt_free


def kind(t):
    if t == 'struct xdp_md *':
        return 'ctx'
    if t.startswith(('bnt_', 'const bnt_')) and t.endswith('*') and 'fib' not in t:
        return 'view'
    return 'ptr' if t.endswith('*') else 'arg'


ARG_BITS = {'__u8': 8, '_Bool': 1, '__u16': 16, '__u32': 32, '__be32': 32}


def model(name, sig, pkt, io):
    """Expected (ret, io after, packet after) of calling name on pkt with io."""
    arg, off, nullmask, _, vout, buf = io[0:4], io[4:8], io[8], io[9], list(io[10:18]), bytearray(io[18])
    p = Pkt(pkt)
    args, slots = [], {}
    for k, t in enumerate(sig['params']):
        if kind(t) == 'view':  # the program stores every view after the call
            vout[2 * k], vout[2 * k + 1] = off[k], 1
    for k, t in enumerate(sig['params']):
        kd = kind(t)
        null = nullmask >> k & 1
        if kd == 'ctx':
            args.append('ctx')
        elif kd == 'view':
            args.append(None if null else View(vout, k, off[k]))
        elif kd == 'ptr':
            args.append(None if null else Slot(buf, k))
            slots[k] = OUT_SIZE.get(t.replace('const ', ''), 0)
        else:
            bits = ARG_BITS[t]
            x = arg[k] & ((1 << bits) - 1) if bits > 1 else int(bool(arg[k]))
            args.append(x)
    if name.endswith(('get_smac', 'get_dmac')) and name.startswith('bnt_fib'):
        args.append(Slot(buf, 1))
    f = API.get(name)
    if f is None and name in GETTERS:
        out_t = sig['params'][1].replace('const ', '')
        f = make_getter(*GETTERS[name], OUT_SIZE[out_t])
    try:
        ret = f(p, *args)
    except Err as e:
        ret = e.code
    if ret != OK and sig['ret'] == 'int':
        pkt_after = None  # unchanged is checked apart
    else:
        pkt_after = bytes(p.b)
    return Expect(ret, (vout, bytes(buf)), pkt_after, slots, True)

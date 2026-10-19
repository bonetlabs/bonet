"""Benchmark traffic and the packets each workload is expected to send back.

The addresses below are the ones hard-coded in the benchmark programs
(validation/{baseline,framework}/xdp_*.c), not testbed settings.
"""

from __future__ import annotations

import socket
import struct
import time
from typing import Dict, List, Mapping, Optional, Sequence, Tuple

TRAFFIC_SRC_IPV4 = "10.8.0.1"     # MMLF blacklist entry
TRAFFIC_DST_IPV4 = "48.0.0.2"     # routed via tg_rx_ipv4; DNAT's old_dst
TRAFFIC_SRC_IPV6 = "fd08::1"      # MMLF6 blacklist entry
TRAFFIC_DST_IPV6 = "fd03::2"      # routed via tg_rx_ipv6; ENCAP's outer dst
UDP_SPORT = 12345
UDP_DPORT = 54321
TTL = 64

MMLF_TOS = 0x2e
DNAT_NEW_DST = "10.7.0.1"
ENCAP_OUTER_SRC = "fd08::2"
ENCAP_OUTER_DST = "fd03::2"
ENCAP_HOP_LIMIT = 64

ETH_P_IP = 0x0800
ETH_P_IPV6 = 0x86DD


def mac(value: str) -> bytes:
    return bytes(int(part, 16) for part in value.split(":"))


def csum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


def _udp(src: bytes, dst: bytes, payload: bytes, with_csum: bool, v6: bool) -> bytes:
    length = 8 + len(payload)
    udp = struct.pack("!HHHH", UDP_SPORT, UDP_DPORT, length, 0)
    if not with_csum:
        return udp + payload
    if v6:
        pseudo = src + dst + struct.pack("!I", length) + b"\x00\x00\x00\x11"
    else:
        pseudo = src + dst + struct.pack("!BBH", 0, socket.IPPROTO_UDP, length)
    value = csum(pseudo + udp + payload) or 0xffff
    return struct.pack("!HHHH", UDP_SPORT, UDP_DPORT, length, value) + payload


def _ipv4(src: bytes, dst: bytes, tos: int, ttl: int, l4: bytes) -> bytes:
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, tos, 20 + len(l4), 1, 0, ttl,
                      socket.IPPROTO_UDP, 0, src, dst)
    return hdr[:10] + struct.pack("!H", csum(hdr)) + hdr[12:] + l4


def _ipv6(src: bytes, dst: bytes, nexthdr: int, hop: int, l4: bytes, flow: int = 0) -> bytes:
    return struct.pack("!IHBB16s16s", (6 << 28) | flow, len(l4), nexthdr, hop, src, dst) + l4


def traffic_frame(experiment: Mapping, net: Mapping, frame_size: int) -> bytes:
    """The frame TRex sends: Ethernet/IPv{4,6}/UDP, frame_size bytes without FCS."""
    eth_dst = mac(net["sut_rx_mac"])
    eth_src = mac(net["tg_tx_mac"])
    with_csum = bool(experiment.get("udp_checksum", False))
    if experiment["traffic"] == "ipv6":
        src = socket.inet_pton(socket.AF_INET6, experiment.get("traffic_src_ipv6", TRAFFIC_SRC_IPV6))
        dst = socket.inet_pton(socket.AF_INET6, experiment.get("traffic_dst_ipv6", TRAFFIC_DST_IPV6))
        payload = bytes(i % 251 for i in range(frame_size - 14 - 40 - 8))
        l3 = _ipv6(src, dst, socket.IPPROTO_UDP, TTL, _udp(src, dst, payload, with_csum, True))
        frame = eth_dst + eth_src + struct.pack("!H", ETH_P_IPV6) + l3
    else:
        src = socket.inet_aton(experiment.get("traffic_src_ipv4", TRAFFIC_SRC_IPV4))
        dst = socket.inet_aton(experiment.get("traffic_dst_ipv4", TRAFFIC_DST_IPV4))
        payload = bytes(i % 251 for i in range(frame_size - 14 - 20 - 8))
        l3 = _ipv4(src, dst, 0, TTL, _udp(src, dst, payload, with_csum, False))
        frame = eth_dst + eth_src + struct.pack("!H", ETH_P_IP) + l3
    if len(frame) != frame_size:
        raise ValueError(f"frame is {len(frame)} bytes, not {frame_size}")
    return frame


def write_pcap(path, frames: Sequence[bytes]) -> None:
    now = int(time.time())
    with open(path, "wb") as handle:
        handle.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for frame in frames:
            handle.write(struct.pack("<IIII", now, 0, len(frame), len(frame)))
            handle.write(frame)


# ---------------------------------------------------------------------------
# Expected output. Each model returns (frame, ignore) where ignore lists the
# byte ranges whose value is not fixed (they are still checked for validity:
# checksums must verify).

Expected = Tuple[bytes, List[Tuple[int, int]]]


def _forwarded_eth(net: Mapping) -> bytes:
    return mac(net["tg_rx_mac"]) + mac(net["sut_tx_mac"])


def _ipv4_parts(frame: bytes) -> Tuple[bytes, bytes]:
    return frame[14:34], frame[34:]


def _expect_ipv4(frame: bytes, net: Mapping, tos: Optional[int] = None,
                 daddr: Optional[str] = None) -> bytes:
    ip, l4 = _ipv4_parts(frame)
    src, dst = ip[12:16], ip[16:20]
    if daddr is not None:
        dst = socket.inet_aton(daddr)
    old_udp_csum = struct.unpack("!H", l4[6:8])[0]
    if old_udp_csum and daddr is not None:
        l4 = _udp(src, dst, l4[8:], True, False)
    new_tos = ip[1] if tos is None else tos
    new_ip = _ipv4(src, dst, new_tos, ip[8] - 1, l4)
    return _forwarded_eth(net) + struct.pack("!H", ETH_P_IP) + new_ip


def expect_mmlf(frame: bytes, net: Mapping, case: str) -> Expected:
    return _expect_ipv4(frame, net, tos=MMLF_TOS), []


def expect_dnat(frame: bytes, net: Mapping, case: str) -> Expected:
    return _expect_ipv4(frame, net, daddr=DNAT_NEW_DST), []


def expect_ip6ip6(frame: bytes, net: Mapping, case: str) -> Expected:
    inner = bytearray(frame[14:])
    ignore: List[Tuple[int, int]] = []
    if case == "kernel":
        # The kernel forwards the inner packet into the tunnel (hop limit - 1)
        # and gives the outer header an automatic flow label.
        inner[7] -= 1
        ignore.append((15, 3))
    outer = _ipv6(socket.inet_pton(socket.AF_INET6, ENCAP_OUTER_SRC),
                  socket.inet_pton(socket.AF_INET6, ENCAP_OUTER_DST),
                  socket.IPPROTO_IPV6, ENCAP_HOP_LIMIT, bytes(inner))
    return _forwarded_eth(net) + struct.pack("!H", ETH_P_IPV6) + outer, ignore


MODELS = {
    "mmlf": expect_mmlf,
    "dnat": expect_dnat,
    "ip6ip6": expect_ip6ip6,
}


def _masked(frame: bytes, ignore: Sequence[Tuple[int, int]]) -> bytes:
    out = bytearray(frame)
    for start, length in ignore:
        out[start:start + length] = b"\x00" * min(length, max(0, len(out) - start))
    return bytes(out)


def describe(frame: bytes) -> str:
    """Short decode for reports."""
    if len(frame) < 14:
        return f"runt {len(frame)}B"
    ethertype = struct.unpack("!H", frame[12:14])[0]
    head = f"{frame[6:12].hex(':')} > {frame[0:6].hex(':')} len={len(frame)}"
    if ethertype == ETH_P_IP and len(frame) >= 34:
        ip = frame[14:34]
        return (f"{head} ipv4 {socket.inet_ntoa(ip[12:16])} > {socket.inet_ntoa(ip[16:20])} "
                f"tos=0x{ip[1]:02x} ttl={ip[8]} proto={ip[9]} csum=0x{ip[10:12].hex()}"
                f" ok={csum(ip) == 0}")
    if ethertype == ETH_P_IPV6 and len(frame) >= 54:
        ip = frame[14:54]
        return (f"{head} ipv6 {socket.inet_ntop(socket.AF_INET6, ip[8:24])} > "
                f"{socket.inet_ntop(socket.AF_INET6, ip[24:40])} nh={ip[6]} hop={ip[7]} "
                f"plen={struct.unpack('!H', ip[4:6])[0]}")
    return f"{head} ethertype=0x{ethertype:04x}"


def is_forwarded(frame: bytes, net: Mapping) -> bool:
    """Whether a captured frame is benchmark traffic sent by the SUT (and not,
    say, an IPv6 neighbor discovery packet of its own)."""
    if len(frame) < 14 or frame[0:6] != mac(net["tg_rx_mac"]):
        return False
    ethertype = struct.unpack("!H", frame[12:14])[0]
    if ethertype == ETH_P_IP:
        return len(frame) >= 34 and frame[23] == socket.IPPROTO_UDP
    if ethertype == ETH_P_IPV6:
        return len(frame) >= 54 and frame[20] in (socket.IPPROTO_UDP, socket.IPPROTO_IPV6)
    return False


def compare(sent: bytes, captured: Sequence[bytes], experiment: Mapping, net: Mapping,
            case: str, count: int) -> Dict[str, object]:
    """Compares the frames TRex captured with the expected output of `count`
    copies of `sent`."""
    forwarded = [frame for frame in captured if is_forwarded(frame, net)]
    model = MODELS.get(experiment.get("expect") or "")
    result: Dict[str, object] = {
        "captured": len(captured),
        "forwarded": len(forwarded),
        "model": experiment.get("expect") or "none",
    }
    if model is None:
        result["matched"] = len(forwarded)
        result["ok"] = len(forwarded) >= count
        result["detail"] = "" if result["ok"] else f"{len(forwarded)}/{count} packets came back"
        return result

    expected, ignore = model(sent, net, case)
    want = _masked(expected, ignore)
    matched = sum(1 for frame in forwarded if _masked(frame, ignore) == want)
    result["matched"] = matched
    result["ok"] = matched >= count
    if result["ok"]:
        result["detail"] = ""
        return result
    wrong = [frame for frame in forwarded if _masked(frame, ignore) != want]
    lines = [f"{matched}/{count} packets as expected, {len(wrong)} different, "
             f"{count - len(forwarded)} missing",
             f"expected: {describe(expected)}"]
    if wrong:
        sample = wrong[0]
        diff = [i for i in range(max(len(sample), len(expected)))
                if i >= len(sample) or i >= len(expected) or sample[i] != expected[i]]
        lines.append(f"got:      {describe(sample)}")
        lines.append(f"differing bytes: {diff[:24]}")
        lines.append(f"got hex:      {sample.hex()}")
        lines.append(f"expected hex: {expected.hex()}")
    result["detail"] = "\n".join(lines)
    return result

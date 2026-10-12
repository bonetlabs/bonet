#!/usr/bin/env bash

set -euo pipefail

ACTION="${1:-help}"
CASE_NAME="${2:-kernel}"

log() {
    printf '[sut] %s\n' "$*"
}

die() {
    printf '[sut] error: %s\n' "$*" >&2
    exit 1
}

need_env() {
    local name="$1"
    if [[ -z "${!name:-}" ]]; then
        die "missing environment variable ${name}"
    fi
}

require_common_env() {
    need_env BONET_ROOT
    need_env SUT_RCV_IFACE
    need_env SUT_RCV_IPV4
    need_env SUT_RCV_PLEN
    need_env SUT_SND_IFACE
    need_env SUT_SND_IPV4
    need_env SUT_SND_PLEN
    need_env TG_RX_IPV4
    need_env TG_RX_MAC
    need_env TRAFFIC_DST_IPV4
    need_env TRAFFIC_DST_PLEN
}

require_ipv6_env() {
    need_env SUT_RCV_IPV6
    need_env SUT_RCV_IPV6_PLEN
    need_env SUT_SND_IPV6
    need_env SUT_SND_IPV6_PLEN
    need_env TG_RX_IPV6
    need_env TRAFFIC_DST_IPV6
    need_env TRAFFIC_DST_IPV6_PLEN
}

resolve_obj() {
    local obj="$1"
    if [[ "${obj}" = /* ]]; then
        printf '%s\n' "${obj}"
    else
        printf '%s/%s\n' "${BONET_ROOT}" "${obj}"
    fi
}

set_iface_mac_if_needed() {
    local iface="$1"
    local mac="$2"

    if [[ -z "${mac}" ]]; then
        ip link set dev "${iface}" up
        return
    fi

    ip link set dev "${iface}" down
    ip link set dev "${iface}" address "${mac}"
    ip link set dev "${iface}" up
}

disable_offloads() {
    local iface="$1"

    if ! command -v ethtool >/dev/null 2>&1; then
        log "ethtool not found, skipping offload tuning on ${iface}"
        return
    fi

    ethtool -K "${iface}" gro off >/dev/null 2>&1 || true
    ethtool -K "${iface}" gso off >/dev/null 2>&1 || true
    ethtool -K "${iface}" tso off >/dev/null 2>&1 || true
    ethtool -K "${iface}" lro off >/dev/null 2>&1 || true
    ethtool -K "${iface}" rx off tx off >/dev/null 2>&1 || true
}

set_irq_affinity_range() {
    local min_irq="$1"
    local max_irq="$2"
    local core="$3"

    if [[ -z "${min_irq}" || -z "${max_irq}" || -z "${core}" ]]; then
        return
    fi

    local irq
    for ((irq = min_irq; irq <= max_irq; irq++)); do
        if [[ -w "/proc/irq/${irq}/smp_affinity_list" ]]; then
            printf '%s\n' "${core}" >"/proc/irq/${irq}/smp_affinity_list" || true
        fi
    done
}

detach_xdp() {
    ip link set dev "${SUT_RCV_IFACE}" xdp off >/dev/null 2>&1 || true
    ip link set dev "${SUT_RCV_IFACE}" xdpgeneric off >/dev/null 2>&1 || true
    ip link set dev "${SUT_RCV_IFACE}" xdpdrv off >/dev/null 2>&1 || true
    ip link set dev "${SUT_RCV_IFACE}" xdpoffload off >/dev/null 2>&1 || true
}

detach_tc() {
    tc filter del dev "${SUT_RCV_IFACE}" ingress >/dev/null 2>&1 || true
    tc qdisc del dev "${SUT_RCV_IFACE}" clsact >/dev/null 2>&1 || true
}

attach_tc() {
    local obj="$1"
    local section="${TC_SECTION:-tc}"

    [[ -f "${obj}" ]] || die "object file not found: ${obj}"

    log "attaching TC ${obj} on ${SUT_RCV_IFACE} ingress section ${section}"
    tc qdisc add dev "${SUT_RCV_IFACE}" clsact 2>/dev/null || true
    tc filter add dev "${SUT_RCV_IFACE}" ingress bpf da obj "${obj}" sec "${section}"
    # TC filter installation causes transient drops for several seconds;
    # sleep here so the measurement window starts after the transient clears.
    sleep "${SUT_TC_SETTLE_SECONDS:-3}"
}

attach_xdp() {
    local obj="$1"
    local mode="${XDP_MODE:-xdp}"
    local section="${XDP_SECTION:-xdp}"

    [[ -f "${obj}" ]] || die "object file not found: ${obj}"

    log "attaching ${obj} on ${SUT_RCV_IFACE} with mode ${mode}"
    ip link set dev "${SUT_RCV_IFACE}" "${mode}" object "${obj}" sec "${section}"
}

configure_common() {
    require_common_env

    log "configuring IPv4 forwarding path"
    detach_xdp
    detach_tc

    set_iface_mac_if_needed "${SUT_RCV_IFACE}" "${SUT_RCV_MAC:-}"
    set_iface_mac_if_needed "${SUT_SND_IFACE}" "${SUT_SND_MAC:-}"

    ip addr replace "${SUT_RCV_IPV4}/${SUT_RCV_PLEN}" dev "${SUT_RCV_IFACE}"
    ip addr replace "${SUT_SND_IPV4}/${SUT_SND_PLEN}" dev "${SUT_SND_IFACE}"

    sysctl -w net.ipv4.ip_forward=1 >/dev/null
    sysctl -w net.ipv4.conf.all.forwarding=1 >/dev/null
    sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null || true
    sysctl -w "net.ipv4.conf.${SUT_RCV_IFACE}.rp_filter=0" >/dev/null || true
    sysctl -w "net.ipv4.conf.${SUT_SND_IFACE}.rp_filter=0" >/dev/null || true

    local traffic_route="${TRAFFIC_DST_ROUTE:-${TRAFFIC_DST_IPV4}/${TRAFFIC_DST_PLEN}}"

    ip neigh replace "${TG_RX_IPV4}" lladdr "${TG_RX_MAC}" dev "${SUT_SND_IFACE}" nud permanent
    ip route replace "${traffic_route}" via "${TG_RX_IPV4}" dev "${SUT_SND_IFACE}"

    disable_offloads "${SUT_RCV_IFACE}"
    disable_offloads "${SUT_SND_IFACE}"

    set_irq_affinity_range "${SUT_RCV_IRQ_MIN:-}" "${SUT_RCV_IRQ_MAX:-}" "${SUT_RCV_IRQ_CORE:-}"
    set_irq_affinity_range "${SUT_SND_IRQ_MIN:-}" "${SUT_SND_IRQ_MAX:-}" "${SUT_SND_IRQ_CORE:-}"
}

setup_kernel_mmlf() {
    [[ -n "${TRAFFIC_SRC_IPV4:-}" ]] || die "TRAFFIC_SRC_IPV4 required for kernel MMLF"
    iptables -t mangle -F PREROUTING
    iptables -t mangle -A PREROUTING \
        -s "${TRAFFIC_SRC_IPV4}/32" -j TOS --set-tos 0x2e
    log "iptables mangle: TOS=0x2e for src ${TRAFFIC_SRC_IPV4}"
}

setup_kernel_mmlf6() {
    [[ -n "${TRAFFIC_SRC_IPV6:-}" ]] || die "TRAFFIC_SRC_IPV6 required for kernel MMLF6"
    ip6tables -t mangle -F PREROUTING
    ip6tables -t mangle -A PREROUTING \
        -s "${TRAFFIC_SRC_IPV6}/128" -j DSCP --set-dscp 0x0b
    log "ip6tables mangle: DSCP=0x0b (TC=0x2e) for src ${TRAFFIC_SRC_IPV6}"
}

setup_kernel_dnat() {
    iptables -t nat -F PREROUTING
    iptables -t nat -A PREROUTING \
        -d "${TRAFFIC_DST_IPV4}/32" -j DNAT --to-destination "${TG_RX_IPV4}"
    log "iptables nat: DNAT ${TRAFFIC_DST_IPV4} -> ${TG_RX_IPV4}"
}

setup_kernel_dnat6() {
    require_ipv6_env
    nft flush table ip6 nat6 2>/dev/null || true
    nft delete table ip6 nat6 2>/dev/null || true
    nft add table ip6 nat6
    nft add chain ip6 nat6 prerouting \
        '{ type nat hook prerouting priority -100; }'
    nft add rule ip6 nat6 prerouting \
        "ip6 daddr ${TRAFFIC_DST_IPV6} dnat to ${TG_RX_IPV6}"
    log "nft nat6: DNAT6 ${TRAFFIC_DST_IPV6} -> ${TG_RX_IPV6}"
}

setup_kernel_ipip() {
    [[ -n "${PCAP_DST_IPV4:-}" ]] || die "PCAP_DST_IPV4 required for kernel IPIP"
    local plen="${PCAP_DST_PLEN:-24}"
    local net
    net=$(python3 -c "import ipaddress; print(ipaddress.ip_network('${PCAP_DST_IPV4}/${plen}', strict=False).network_address)")
    ip tunnel del ipip0 2>/dev/null || true
    ip tunnel add ipip0 mode ipip \
        local "${SUT_RCV_IPV4}" remote "${TRAFFIC_DST_IPV4}"
    ip link set ipip0 up
    ip route replace "${net}/${plen}" dev ipip0
    log "IPIP tunnel ${SUT_RCV_IPV4}<->${TRAFFIC_DST_IPV4}, inner ${net}/${plen}"
}

setup_kernel_ip6ip6() {
    require_ipv6_env
    [[ -n "${PCAP_DST_IPV6:-}" ]] || die "PCAP_DST_IPV6 required for kernel IP6IP6"
    local plen="${PCAP_DST_IPV6_PLEN:-64}"
    local net
    net=$(python3 -c "import ipaddress, os; print(ipaddress.ip_network(os.environ['PCAP_DST_IPV6'] + '/' + os.environ.get('PCAP_DST_IPV6_PLEN', '64'), strict=False))")
    ip -6 tunnel del ip6ip6_tun 2>/dev/null || true
    ip -6 tunnel add ip6ip6_tun mode ip6ip6 \
        local "${SUT_RCV_IPV6}" remote "${TRAFFIC_DST_IPV6}" ttl 64
    ip link set ip6ip6_tun up
    ip -6 route replace "${net}" dev ip6ip6_tun
    log "IP6IP6 tunnel ${SUT_RCV_IPV6}<->${TRAFFIC_DST_IPV6}, inner ${net}"
}

setup_kernel_srv6_encap() {
    require_ipv6_env
    [[ -n "${PCAP_DST_IPV4:-}" ]] || die "PCAP_DST_IPV4 required for kernel SRv6 encap"
    local plen="${PCAP_DST_PLEN:-24}"
    local inner_net
    inner_net=$(python3 -c "import ipaddress; print(ipaddress.ip_network('${PCAP_DST_IPV4}/${plen}', strict=False))")
    sysctl -w "net.ipv6.conf.${SUT_SND_IFACE}.seg6_enabled=1" >/dev/null
    ip route replace "${inner_net}" \
        encap seg6 mode encap segs "${TG_RX_IPV6}" \
        dev "${SUT_SND_IFACE}"
    log "SRv6 encap: ${inner_net} encap seg6 segs ${TG_RX_IPV6}"
}

configure_common_v6() {
    require_common_env
    require_ipv6_env

    log "configuring IPv6 forwarding path"
    detach_xdp
    detach_tc

    set_iface_mac_if_needed "${SUT_RCV_IFACE}" "${SUT_RCV_MAC:-}"
    set_iface_mac_if_needed "${SUT_SND_IFACE}" "${SUT_SND_MAC:-}"

    ip addr replace "${SUT_RCV_IPV4}/${SUT_RCV_PLEN}" dev "${SUT_RCV_IFACE}"
    ip addr replace "${SUT_SND_IPV4}/${SUT_SND_PLEN}" dev "${SUT_SND_IFACE}"
    ip -6 addr replace "${SUT_RCV_IPV6}/${SUT_RCV_IPV6_PLEN}" dev "${SUT_RCV_IFACE}"
    ip -6 addr replace "${SUT_SND_IPV6}/${SUT_SND_IPV6_PLEN}" dev "${SUT_SND_IFACE}"

    sysctl -w net.ipv4.ip_forward=1 >/dev/null
    sysctl -w net.ipv4.conf.all.forwarding=1 >/dev/null
    sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null || true
    sysctl -w "net.ipv4.conf.${SUT_RCV_IFACE}.rp_filter=0" >/dev/null || true
    sysctl -w "net.ipv4.conf.${SUT_SND_IFACE}.rp_filter=0" >/dev/null || true
    sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null
    sysctl -w "net.ipv6.conf.${SUT_RCV_IFACE}.forwarding=1" >/dev/null
    sysctl -w "net.ipv6.conf.${SUT_SND_IFACE}.forwarding=1" >/dev/null

    ip neigh replace "${TG_RX_IPV4}" lladdr "${TG_RX_MAC}" dev "${SUT_SND_IFACE}" nud permanent
    ip route replace "${TRAFFIC_DST_ROUTE:-${TRAFFIC_DST_IPV4}/${TRAFFIC_DST_PLEN}}" via "${TG_RX_IPV4}" dev "${SUT_SND_IFACE}"

    ip -6 neigh replace "${TG_RX_IPV6}" lladdr "${TG_RX_MAC}" dev "${SUT_SND_IFACE}" nud permanent
    ip -6 route replace "${TRAFFIC_DST_IPV6_ROUTE:-${TRAFFIC_DST_IPV6}/${TRAFFIC_DST_IPV6_PLEN}}" via "${TG_RX_IPV6}" dev "${SUT_SND_IFACE}"

    disable_offloads "${SUT_RCV_IFACE}"
    disable_offloads "${SUT_SND_IFACE}"

    set_irq_affinity_range "${SUT_RCV_IRQ_MIN:-}" "${SUT_RCV_IRQ_MAX:-}" "${SUT_RCV_IRQ_CORE:-}"
    set_irq_affinity_range "${SUT_SND_IRQ_MIN:-}" "${SUT_SND_IRQ_MAX:-}" "${SUT_SND_IRQ_CORE:-}"
}

prepare_case() {
    local case_name="$1"
    local ip_ver="${EXPERIMENT_IP_VERSION:-4}"

    if [[ "${ip_ver}" == "6" || "${ip_ver}" == "srv6" ]]; then
        configure_common_v6
    else
        configure_common
    fi

    case "${case_name}" in
        framework)
            need_env FRAMEWORK_OBJ
            attach_xdp "$(resolve_obj "${FRAMEWORK_OBJ}")"
            ;;
        framework-inlined)
            need_env FRAMEWORK_INLINED_OBJ
            attach_xdp "$(resolve_obj "${FRAMEWORK_INLINED_OBJ}")"
            ;;
        baseline)
            need_env BASELINE_OBJ
            attach_xdp "$(resolve_obj "${BASELINE_OBJ}")"
            ;;
        framework-tc)
            need_env FRAMEWORK_TC_OBJ
            attach_tc "$(resolve_obj "${FRAMEWORK_TC_OBJ}")"
            ;;
        baseline-tc)
            need_env BASELINE_TC_OBJ
            attach_tc "$(resolve_obj "${BASELINE_TC_OBJ}")"
            ;;
        kernel)
            log "kernel forwarding: experiment=${EXPERIMENT_NAME:-plain} ip_version=${ip_ver}"
            case "${EXPERIMENT_NAME:-}" in
                mmlf6*)      setup_kernel_mmlf6 ;;
                mmlf*)       setup_kernel_mmlf ;;
                srv6*)       setup_kernel_srv6_encap ;;
                ip6ip6*)     setup_kernel_ip6ip6 ;;
                ipip*)       setup_kernel_ipip ;;
                *dnat6*)     setup_kernel_dnat6 ;;
                *dnat*)      setup_kernel_dnat ;;
                ipv6-*)      log "plain IPv6 kernel forwarding" ;;
                *)           log "plain IPv4 kernel forwarding" ;;
            esac
            ;;
        *)
            die "unsupported case: ${case_name}"
            ;;
    esac
}

clean_case() {
    require_common_env

    local traffic_route="${TRAFFIC_DST_ROUTE:-${TRAFFIC_DST_IPV4}/${TRAFFIC_DST_PLEN}}"

    log "cleaning benchmark forwarding state"
    detach_xdp
    detach_tc
    ip route del "${traffic_route}" >/dev/null 2>&1 || true
    ip neigh del "${TG_RX_IPV4}" dev "${SUT_SND_IFACE}" >/dev/null 2>&1 || true
    iptables -t mangle -F PREROUTING 2>/dev/null || true
    iptables -t nat -F PREROUTING 2>/dev/null || true
    ip link set ipip0 down 2>/dev/null || true
    ip tunnel del ipip0 2>/dev/null || true
    ip link set ip6ip6_tun down 2>/dev/null || true
    ip -6 tunnel del ip6ip6_tun 2>/dev/null || true
    if [[ -n "${PCAP_DST_IPV4:-}" && -n "${PCAP_DST_PLEN:-}" ]]; then
        local pcap_net
        pcap_net=$(python3 -c "import ipaddress; print(ipaddress.ip_network('${PCAP_DST_IPV4}/${PCAP_DST_PLEN}', strict=False))" 2>/dev/null || true)
        [[ -n "${pcap_net}" ]] && ip route del "${pcap_net}" >/dev/null 2>&1 || true
    fi

    # IPv6 cleanup (safe to run even for IPv4 experiments)
    ip6tables -t mangle -F PREROUTING 2>/dev/null || true
    nft delete table ip6 nat6 2>/dev/null || true
    if [[ -n "${TRAFFIC_DST_IPV6_ROUTE:-}" ]]; then
        ip -6 route del "${TRAFFIC_DST_IPV6_ROUTE}" >/dev/null 2>&1 || true
    elif [[ -n "${TRAFFIC_DST_IPV6:-}" && -n "${TRAFFIC_DST_IPV6_PLEN:-}" ]]; then
        ip -6 route del "${TRAFFIC_DST_IPV6}/${TRAFFIC_DST_IPV6_PLEN}" >/dev/null 2>&1 || true
    fi
    if [[ -n "${TG_RX_IPV6:-}" && -n "${SUT_SND_IFACE:-}" ]]; then
        ip -6 neigh del "${TG_RX_IPV6}" dev "${SUT_SND_IFACE}" >/dev/null 2>&1 || true
    fi
}

usage() {
    cat <<EOF
Usage:
  $0 prepare {framework|framework-inlined|baseline|framework-tc|baseline-tc|kernel}
  $0 clean kernel

The script is configured through environment variables generated by
validation/perf/runner.py. It configures IPv4 forwarding, static neighbor state,
the route for benchmark traffic, optional NIC tuning, and the selected XDP
program.
EOF
}

case "${ACTION}" in
    prepare)
        prepare_case "${CASE_NAME}"
        ;;
    clean)
        clean_case
        ;;
    help|--help|-h)
        usage
        ;;
    *)
        usage
        die "unsupported action: ${ACTION}"
        ;;
esac

#!/usr/bin/env bash
# SUT side of the benchmark, run as root by bench/runner.py over ssh.
#
#   sut.sh prepare   configure forwarding and attach the case (HOOK, OBJ, KERNEL_SETUP)
#   sut.sh counters  kernel-forwarded packets and RX interrupts per CPU
#   sut.sh prog      the attached XDP/TC program, as bpftool JSON
#   sut.sh stats_on, stats_off   kernel.bpf_stats_enabled
#   sut.sh stats     run_time_ns and run_cnt of the attached program
#   sut.sh info      machine description for the run metadata
#   sut.sh clean     undo prepare
#
# Settings come from the environment (see runner.py: sut_env()).

set -euo pipefail

ACTION="${1:-help}"

log() { printf '[sut] %s\n' "$*" >&2; }
die() { printf '[sut] error: %s\n' "$*" >&2; exit 1; }

RX="${SUT_RX_IFACE:-}"
TX="${SUT_TX_IFACE:-}"

pci_of() { basename "$(readlink -f "/sys/class/net/$1/device")"; }

# IRQ of completion queue $2 of interface $1.
queue_irq() {
    grep -E "mlx5_comp$2@pci:$(pci_of "$1")\$" /proc/interrupts | cut -d: -f1 | tr -d ' '
}

detach_all() {
    local mode
    for mode in xdp xdpgeneric xdpdrv xdpoffload; do
        ip link set dev "${RX}" "${mode}" off >/dev/null 2>&1 || true
    done
    tc filter del dev "${RX}" ingress >/dev/null 2>&1 || true
    tc qdisc del dev "${RX}" clsact >/dev/null 2>&1 || true
}

kernel_state_clean() {
    iptables -t mangle -F PREROUTING 2>/dev/null || true
    iptables -t nat -F PREROUTING 2>/dev/null || true
    ip6tables -t mangle -F PREROUTING 2>/dev/null || true
    nft delete table ip6 nat6 2>/dev/null || true
    ip tunnel del ipip0 2>/dev/null || true
    ip -6 tunnel del ip6ip6_tun 2>/dev/null || true
    ip route del 10.100.0.0/24 >/dev/null 2>&1 || true
    ip -6 route del fd04::/64 >/dev/null 2>&1 || true
}

disable_offloads() {
    local opt
    for opt in gro gso tso lro; do
        ethtool -K "$1" "${opt}" off >/dev/null 2>&1 || true
    done
    ethtool -K "$1" rx off tx off >/dev/null 2>&1 || true
}

# Steer all traffic to RX_QUEUE and pin that queue's interrupt, on both
# interfaces, to RX_CPU (XDP_REDIRECT transmits on the queue of the current
# CPU, so the TX side completes there too).
pin_queue() {
    local nq weights i irq dev
    nq=$(ethtool -l "${RX}" | awk '/Current hardware settings/{c=1} c && /Combined/{print $2; exit}')
    (( RX_QUEUE < nq )) || die "rx_queue ${RX_QUEUE} >= ${nq} channels on ${RX}"
    weights=""
    for ((i = 0; i < nq; i++)); do
        if (( i == RX_QUEUE )); then weights+=" 1"; else weights+=" 0"; fi
    done
    # shellcheck disable=SC2086
    ethtool -X "${RX}" weight ${weights}
    for dev in "${RX}" "${TX}"; do
        irq=$(queue_irq "${dev}" "${RX_QUEUE}")
        [[ -n "${irq}" ]] || die "no mlx5_comp${RX_QUEUE} interrupt for ${dev}"
        echo "${RX_CPU}" >"/proc/irq/${irq}/smp_affinity_list"
    done
}

configure() {
    detach_all
    kernel_state_clean
    systemctl stop irqbalance 2>/dev/null || true

    ip link set dev "${RX}" up
    ip link set dev "${TX}" up
    ip addr replace "${SUT_RX_IPV4}/${SUT_RX_PREFIX}" dev "${RX}"
    ip addr replace "${SUT_TX_IPV4}/${SUT_TX_PREFIX}" dev "${TX}"
    ip -6 addr replace "${SUT_RX_IPV6}/${SUT_RX_IPV6_PREFIX}" dev "${RX}" nodad
    ip -6 addr replace "${SUT_TX_IPV6}/${SUT_TX_IPV6_PREFIX}" dev "${TX}" nodad

    sysctl -qw net.ipv4.ip_forward=1
    sysctl -qw net.ipv4.conf.all.forwarding=1
    sysctl -qw net.ipv4.conf.all.rp_filter=0
    sysctl -qw "net.ipv4.conf.${RX}.rp_filter=0"
    sysctl -qw "net.ipv4.conf.${TX}.rp_filter=0"
    sysctl -qw net.ipv6.conf.all.forwarding=1

    ip neigh replace "${TG_RX_IPV4}" lladdr "${TG_RX_MAC}" dev "${TX}" nud permanent
    ip -6 neigh replace "${TG_RX_IPV6}" lladdr "${TG_RX_MAC}" dev "${TX}" nud permanent
    ip route replace 48.0.0.0/24 via "${TG_RX_IPV4}" dev "${TX}"
    ip -6 route replace fd03::/64 via "${TG_RX_IPV6}" dev "${TX}"

    disable_offloads "${RX}"
    disable_offloads "${TX}"
}

kernel_setup() {
    case "${KERNEL_SETUP:-}" in
        "") log "plain kernel forwarding" ;;
        mmlf)
            iptables -t mangle -A PREROUTING -s 10.8.0.1/32 -j TOS --set-tos 0x2e ;;
        mmlf6)
            ip6tables -t mangle -A PREROUTING -s fd08::1/128 -j DSCP --set-dscp 0x0b ;;
        dnat)
            iptables -t nat -A PREROUTING -d 48.0.0.2/32 -j DNAT --to-destination "${TG_RX_IPV4}" ;;
        dnat6)
            nft add table ip6 nat6
            nft add chain ip6 nat6 prerouting '{ type nat hook prerouting priority -100; }'
            nft add rule ip6 nat6 prerouting "ip6 daddr fd03::2 dnat to ${TG_RX_IPV6}" ;;
        ipip)
            ip tunnel add ipip0 mode ipip local "${SUT_RX_IPV4}" remote 48.0.0.2
            ip link set ipip0 up
            ip route replace 10.100.0.0/24 dev ipip0 ;;
        ip6ip6)
            # No encapsulation-limit option, like the XDP programs.
            ip -6 tunnel add ip6ip6_tun mode ip6ip6 local "${SUT_RX_IPV6}" remote fd03::2 \
                ttl 64 encaplimit none
            ip link set ip6ip6_tun up
            ip -6 route replace fd04::/64 dev ip6ip6_tun ;;
        srv6)
            sysctl -qw "net.ipv6.conf.${TX}.seg6_enabled=1"
            ip route replace 10.100.0.0/24 encap seg6 mode encap segs "${TG_RX_IPV6}" dev "${TX}" ;;
        *) die "unknown kernel setup: ${KERNEL_SETUP}" ;;
    esac
}

prepare() {
    configure
    case "${HOOK}" in
        xdp)
            [[ -f "${OBJ}" ]] || die "object not found: ${OBJ}"
            ip link set dev "${RX}" xdpdrv object "${OBJ}" sec xdp ;;
        tc)
            [[ -f "${OBJ}" ]] || die "object not found: ${OBJ}"
            tc qdisc add dev "${RX}" clsact
            tc filter add dev "${RX}" ingress bpf da obj "${OBJ}" sec tc ;;
        kernel)
            kernel_setup ;;
        *) die "unknown hook: ${HOOK}" ;;
    esac
    # After the attach: mlx5 reopens its channels when an XDP program appears.
    pin_queue
    log "prepared ${HOOK} ${OBJ:-} ${KERNEL_SETUP:-}"
}

counters() {
    awk '/^Ip: [0-9]/ {print "IpForwDatagrams", $7}' /proc/net/snmp
    awk '$1 == "Ip6OutForwDatagrams" {print "Ip6OutForwDatagrams", $2}' /proc/net/snmp6
    # Completion interrupts of the RX interface, summed per CPU.
    grep -E "mlx5_comp[0-9]+@pci:$(pci_of "${RX}")\$" /proc/interrupts |
        awk -v n="$(nproc)" '{for (c = 0; c < n; c++) s[c] += $(c + 2)}
             END {printf "rx_irqs"; for (c = 0; c < n; c++) printf " %d", s[c]; print ""}'
}

prog() {
    local id
    id=$(ip -j link show dev "${RX}" | python3 -c 'import json,sys; d=json.load(sys.stdin)[0]; print(d.get("xdp",{}).get("prog",{}).get("id",""))')
    if [[ -z "${id}" ]]; then
        id=$(tc -j filter show dev "${RX}" ingress 2>/dev/null |
             python3 -c 'import json,sys; print(next((f["options"]["prog"]["id"] for f in json.load(sys.stdin) if "prog" in f.get("options",{})), ""))' 2>/dev/null || true)
    fi
    if [[ -n "${id}" ]]; then bpftool -j prog show id "${id}"; else echo '{}'; fi
}

# Per-program run time and run count, kept by the kernel while
# kernel.bpf_stats_enabled is 1 (it costs two clock reads per run, so it is on
# only around the runtime trials).
stats_on() { sysctl -qw kernel.bpf_stats_enabled=1; }
stats_off() { sysctl -qw kernel.bpf_stats_enabled=0; }

stats() {
    prog | python3 -c 'import json,sys; d=json.load(sys.stdin); print("run_time_ns", d.get("run_time_ns", 0)); print("run_cnt", d.get("run_cnt", 0))'
}

info() {
    echo "kernel: $(uname -r)"
    echo "os: $(. /etc/os-release; echo "${PRETTY_NAME}")"
    echo "cpu: $(lscpu | awk -F: '/Model name/{gsub(/^ +/,"",$2); print $2}')"
    echo "cpus: $(nproc)"
    echo "rx_driver: $(ethtool -i "${RX}" | tr '\n' ' ')"
    echo "rx_channels: $(ethtool -l "${RX}" | awk '/Current/{c=1} c && /Combined/{print $2; exit}')"
    echo "irqbalance: $(systemctl is-active irqbalance 2>/dev/null || true)"
    echo "bpftool: $(bpftool version | head -1)"
}

clean() {
    stats_off
    detach_all
    kernel_state_clean
    ethtool -X "${RX}" default >/dev/null 2>&1 || true
    ip route del 48.0.0.0/24 >/dev/null 2>&1 || true
    ip -6 route del fd03::/64 >/dev/null 2>&1 || true
    ip neigh del "${TG_RX_IPV4}" dev "${TX}" >/dev/null 2>&1 || true
    ip -6 neigh del "${TG_RX_IPV6}" dev "${TX}" >/dev/null 2>&1 || true
    log "cleaned"
}

case "${ACTION}" in
    prepare) prepare ;;
    counters) counters ;;
    prog) prog ;;
    stats_on) stats_on ;;
    stats_off) stats_off ;;
    stats) stats ;;
    info) info ;;
    clean) clean ;;
    *) sed -n '2,10p' "$0"; exit 2 ;;
esac

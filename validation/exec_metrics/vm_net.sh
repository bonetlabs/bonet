#!/bin/sh
# Set up the network the workload cases expect, so that bpf_fib_lookup succeeds
# (run as root, in a scratch VM: it changes routes and forwarding settings).
# XDP test runs come in on lo; the routes leave on veth v0 through a permanent
# neighbour. MAC addresses as in workloads.py (FIB). With an XDP object as
# argument (../micro_perf/build/sink.o), it is attached to v1, so that packets
# sent out of v0 by XDP_TX or XDP_REDIRECT are accepted. Prints the ifindex
# of v0.
set -e
ip link set lo up
sysctl -qw net.ipv4.conf.all.forwarding=1 net.ipv4.conf.lo.forwarding=1
sysctl -qw net.ipv6.conf.all.forwarding=1 net.ipv6.conf.lo.forwarding=1
ip link add v0 address 02:00:00:00:01:01 type veth peer name v1 address 02:00:00:00:01:02
ip link set v0 up
ip link set v1 up
ip addr add 10.9.0.1/24 dev v0
ip -6 addr add fd09::1/64 dev v0 nodad
ip neigh add 10.9.0.2 lladdr 02:00:00:00:02:02 dev v0 nud permanent
ip -6 neigh add fd09::2 lladdr 02:00:00:00:02:02 dev v0 nud permanent
for n in 48.0.0.0/8 10.7.0.0/16; do ip route add $n via 10.9.0.2 dev v0; done
for n in fd03::/16 fd07::/16; do ip -6 route add $n via fd09::2 dev v0; done
sysctl -qw net.ipv4.conf.v0.forwarding=1 net.ipv6.conf.v0.forwarding=1
[ -n "$1" ] && ip link set dev v1 xdp obj "$1" sec xdp
cat /sys/class/net/v0/ifindex

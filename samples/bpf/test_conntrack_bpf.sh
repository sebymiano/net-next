#!/bin/bash
DEV=enp0s16

tc qdisc del dev enp0s16 clsact
rmmod nf_conntrack_ipv4
rmmod nf_defrag_ipv4

set -ex
modprobe nf_defrag_ipv4
modprobe nf_conntrack_ipv4

echo 'module nf_conntrack +p' > /sys/kernel/debug/dynamic_debug/control
echo 'module nf_conntrack_ipv4 +p' > /sys/kernel/debug/dynamic_debug/control
echo 'module ip_fragment +p' > /sys/kernel/debug/dynamic_debug/control
echo 'module icmp +p' > /sys/kernel/debug/dynamic_debug/control

tc qdisc add dev enp0s16 clsact
tc filter add dev enp0s16 ingress bpf da obj tcbpf3_kern.o sec ct_lookup
tc filter add dev enp0s16  egress bpf da obj tcbpf3_kern.o sec ct_commit

exit 0

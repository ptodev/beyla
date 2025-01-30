#include "vmlinux.h"
#include "bpf_helpers.h"
#include "map_sizing.h"
#include "bpf_dbg.h"
#include "pid.h"
#include "bpf_tracing.h"

// #include "sockaddr.h"
// #include "tcp_info.h"
// #include "k_tracer_defs.h"
// #include "http_ssl_defs.h"
// #include "pin_internal.h"
// #include "k_send_receive.h"
// #include "k_unix_sock.h"

char __license[] SEC("license") = "Dual MIT/GPL";

// Temporary tracking of capabilities
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __type(key, u64);
    __type(value, int);
} capability_events SEC(".maps");

SEC("kprobe/capable")
int BPF_KPROBE(beyla_kprobe_capable, int cap) {
    u64 id = bpf_get_current_pid_tgid();

    //TODO: Log the system time. Can we use bpf_ktime_get_tai_ns?
    // https://docs.ebpf.io/linux/helper-function/bpf_ktime_get_tai_ns/
    bpf_map_update_elem(&capability_events, &id, &cap, BPF_ANY);

    //TODO: Why are the Alloy processes not considered valid?
    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("=== capable id=%d ===", id);

    return 0;
}

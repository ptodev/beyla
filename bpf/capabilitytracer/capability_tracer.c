#include "bpfcore/vmlinux.h"
#include "bpfcore/bpf_helpers.h"
#include "common/map_sizing.h"
#include "logger/bpf_dbg.h"
#include "pid/pid.h"
#include "bpfcore/bpf_tracing.h"

char __license[] SEC("license") = "Dual MIT/GPL";

typedef struct capability_info {
    int cap;
    int pid;
} capability_info_t;

const capability_info_t *unused_2 __attribute__((unused));

// Temporary tracking of capabilities
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 12);
} capability_events SEC(".maps");

SEC("kprobe/capable")
int BPF_KPROBE(beyla_kprobe_capable, int cap) {
    u64 id = bpf_get_current_pid_tgid();

    bpf_dbg_printk("=== capable() was called by pid %d for capability %d ===", id, cap);

    return 0;
}

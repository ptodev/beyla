#include "bpfcore/vmlinux.h"
#include "bpfcore/bpf_helpers.h"
#include "common/map_sizing.h"
#include "logger/bpf_dbg.h"
#include "pid/pid.h"
#include "bpfcore/bpf_tracing.h"

char __license[] SEC("license") = "Dual MIT/GPL";

SEC("kprobe/capable")
int BPF_KPROBE(beyla_kprobe_capable, int cap) {
    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wunused-variable"

    u64 id = bpf_get_current_pid_tgid();

    bpf_dbg_printk("=== capable() was called by pid %d for capability %d ===", id, cap);

    #pragma GCC diagnostic pop

    return 0;
}

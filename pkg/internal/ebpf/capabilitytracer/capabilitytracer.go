// Do we need a "go:build linux"? Beyla is Linux-only anyway.

package capabilitytracer

import (
	"context"
	"io"
	"log/slog"

	"github.com/cilium/ebpf"

	"github.com/grafana/beyla/v2/pkg/beyla"
	"github.com/grafana/beyla/v2/pkg/config"
	beyla_ebpf "github.com/grafana/beyla/v2/pkg/internal/ebpf"
	ebpfcommon "github.com/grafana/beyla/v2/pkg/internal/ebpf/common"
	"github.com/grafana/beyla/v2/pkg/internal/ebpf/ringbuf"
	"github.com/grafana/beyla/v2/pkg/internal/exec"
	"github.com/grafana/beyla/v2/pkg/internal/goexec"
	"github.com/grafana/beyla/v2/pkg/internal/imetrics"
	"github.com/grafana/beyla/v2/pkg/internal/request"
	"github.com/grafana/beyla/v2/pkg/internal/svc"
	"github.com/grafana/beyla/v2/pkg/pipe/msg"
)

//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -type capability_info_t -target amd64,arm64 bpf ../../../../bpf/capabilitytracer/capability_tracer.c -- -I../../../../bpf
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -type capability_info_t -target amd64,arm64 bpf_tp ../../../../bpf/capabilitytracer/capability_tracer.c -- -I../../../../bpf -DBPF_TRACEPARENT
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -type capability_info_t -target amd64,arm64 bpf_debug ../../../../bpf/capabilitytracer/capability_tracer.c -- -I../../../../bpf -DBPF_DEBUG
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -type capability_info_t -target amd64,arm64 bpf_tp_debug ../../../../bpf/capabilitytracer/capability_tracer.c -- -I../../../../bpf -DBPF_DEBUG -DBPF_TRACEPARENT

type BPFCapabilityInfo bpfCapabilityInfoT

type Tracer struct {
	cfg        *beyla.Config
	bpfObjects bpfObjects
	closers    []io.Closer
	log        *slog.Logger
}

// AddInstrumentedLibRef implements ebpf.Tracer.
func (p *Tracer) AddInstrumentedLibRef(uint64) {
}

func (p *Tracer) AllowPID(pid, ns uint32, svc *svc.Attrs) {}

func (p *Tracer) BlockPID(pid, ns uint32) {}

// AlreadyInstrumentedLib implements ebpf.Tracer.
func (p *Tracer) AlreadyInstrumentedLib(uint64) bool {
	return false
}

// Constants implements ebpf.Tracer.
func (p *Tracer) Constants() map[string]any {
	return nil
}

// GoProbes implements ebpf.Tracer.
func (p *Tracer) GoProbes() map[string][]*ebpfcommon.ProbeDesc {
	return nil
}

// ProcessBinary implements ebpf.Tracer.
func (p *Tracer) ProcessBinary(*exec.FileInfo) {
}

// RecordInstrumentedLib implements ebpf.Tracer.
func (p *Tracer) RecordInstrumentedLib(uint64, []io.Closer) {
}

// RegisterOffsets implements ebpf.Tracer.
func (p *Tracer) RegisterOffsets(*exec.FileInfo, *goexec.Offsets) {
}

// SockMsgs implements ebpf.Tracer.
func (p *Tracer) SockMsgs() []ebpfcommon.SockMsg {
	return nil
}

// SockOps implements ebpf.Tracer.
func (p *Tracer) SockOps() []ebpfcommon.SockOps {
	return nil
}

// SocketFilters implements ebpf.Tracer.
func (p *Tracer) SocketFilters() []*ebpf.Program {
	return nil
}

// UProbes implements ebpf.Tracer.
func (p *Tracer) UProbes() map[string]map[string][]*ebpfcommon.ProbeDesc {
	return nil
}

// UnlinkInstrumentedLib implements ebpf.Tracer.
func (p *Tracer) UnlinkInstrumentedLib(uint64) {
}

var _ beyla_ebpf.Tracer = (*Tracer)(nil)

func New(cfg *beyla.Config, metrics imetrics.Reporter) *Tracer {
	log := slog.With("component", "capabilitytracer.Tracer")
	return &Tracer{
		log: log,
		cfg: cfg,
	}
}

func (p *Tracer) Load() (*ebpf.CollectionSpec, error) {
	loader := loadBpf
	if p.cfg.EBPF.BpfDebug {
		loader = loadBpf_debug
	}

	return loader()
}

func (p *Tracer) BpfObjects() any {
	return &p.bpfObjects
}

func (p *Tracer) AddCloser(c ...io.Closer) {
	p.closers = append(p.closers, c...)
}

func (p *Tracer) KProbes() map[string]ebpfcommon.ProbeDesc {
	kprobes := map[string]ebpfcommon.ProbeDesc{
		"capable": {
			Required: true,
			Start:    p.bpfObjects.BeylaKprobeCapable,
		},
	}

	return kprobes
}

func (p *Tracer) Tracepoints() map[string]ebpfcommon.ProbeDesc {
	return nil
}

func (p *Tracer) SetupTailCalls() {}

func (p *Tracer) Run(ctx context.Context, eventsChan *msg.Queue[[]request.Span]) {
	ebpfcommon.ForwardRingbuf(
		&p.cfg.EBPF,
		p.bpfObjects.CapabilityEvents,
		&ebpfcommon.IdentityPidsFilter{},
		p.process,
		p.log,
		imetrics.NoopReporter{},
		append(p.closers, &p.bpfObjects)...,
	)(ctx, eventsChan)
}

func (p *Tracer) process(_ *config.EBPFTracer, record *ringbuf.Record, _ ebpfcommon.ServiceFilter) (request.Span, bool, error) {
	return request.Span{}, true, nil
}

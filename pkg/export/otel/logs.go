package otel

import (
	"context"
	"fmt"

	"github.com/mariomac/pipes/pipe"
	sdklog "go.opentelemetry.io/otel/sdk/log"

	"github.com/grafana/beyla/pkg/export/attributes"
	"github.com/grafana/beyla/pkg/export/instrumentations"
	instrument "github.com/grafana/beyla/pkg/export/otel/metric/api/metric"
	"github.com/grafana/beyla/pkg/internal/pipe/global"
	"github.com/grafana/beyla/pkg/internal/request"
	"github.com/grafana/beyla/pkg/internal/svc"
)

type LogsConfig struct {
	//TODO: Add more config arguments
	CommonEndpoint string `yaml:"-" env:"OTEL_EXPORTER_OTLP_ENDPOINT"`
}

func (lc *LogsConfig) Enabled() bool {
	//TODO: Implement later
	return true
}

// LogsReporter implements the graph node that receives request.Span
// instances and forwards them as OTEL logs.
type LogsReporter struct {
	ctx        context.Context
	cfg        *LogsConfig
	hostID     string
	attributes *attributes.AttrSelector
	exporter   sdklog.Exporter
	reporters  ReporterPool[*svc.Attrs, *Logs]
	is         instrumentations.InstrumentationSelection
}

func newLogsReporter(
	ctx context.Context,
	ctxInfo *global.ContextInfo,
	cfg *LogsConfig,
	userAttribSelection attributes.Selection,
) (*LogsReporter, error) {
	// log := mlog()

	lr := LogsReporter{}

	// lr.reporters = NewReporterPool[*svc.Attrs, *Logs](cfg.ReportersCacheLen, cfg.TTL, timeNow,
	// 	func(id svc.UID, v *expirable[*Logs]) {
	// 		llog := log.With("service", id)
	// 		llog.Debug("evicting logs reporter from cache")
	// 		// v.value.cleanupAllLogsInstances()
	// 		go func() {
	// 			if err := v.value.provider.ForceFlush(ctx); err != nil {
	// 				llog.Warn("error flushing evicted logs provider", "error", err)
	// 			}
	// 		}()
	// 	}, mr.newLogsSet)
	// Instantiate the OTLP HTTP or GRPC logs exporter
	// exporter, err := InstantiateLogsExporter(ctx, cfg, log)
	// if err != nil {
	// 	return nil, err
	// }
	// lr.exporter = exporter

	return &lr, nil
}

func (mr *LogsReporter) reportLogs(input <-chan []request.Span) {
	for spans := range input {
		for i := range spans {
			s := &spans[i]
			fmt.Println("Hello from reportMetrics", s)

			// if s.InternalSignal() {
			// 	continue
			// }
			// // If we are ignoring this span because of route patterns, don't do anything
			// if s.IgnoreMetrics() {
			// 	continue
			// }
			// reporter, err := mr.reporters.For(&s.Service)
			// if err != nil {
			// 	mlog().Error("unexpected error creating OTEL resource. Ignoring metric",
			// 		"error", err, "service", s.Service)
			// 	continue
			// }
			// reporter.record(s, mr)
		}
	}
	// mr.close()
}

// Logs is a set of logs associated to a given OTEL MeterProvider.
// There is a Logs instance for each service/process instrumented by Beyla.
type Logs struct {
	ctx     context.Context
	service *svc.Attrs

	// IMPORTANT! Don't forget to clean each Expirer in cleanupAllLogsInstances method
	capabilities *Expirer[*request.Span, instrument.Float64Histogram, float64]
}

func ReportLogs(
	ctx context.Context,
	ctxInfo *global.ContextInfo,
	cfg *LogsConfig,
	userAttribSelection attributes.Selection,
) pipe.FinalProvider[[]request.Span] {
	return func() (pipe.FinalFunc[[]request.Span], error) {
		fmt.Println("Hello from ReportLogs")
		if !cfg.Enabled() {
			return pipe.IgnoreFinal[[]request.Span](), nil
		}

		mr, err := newLogsReporter(ctx, ctxInfo, cfg, userAttribSelection)
		if err != nil {
			return nil, fmt.Errorf("instantiating OTEL logs reporter: %w", err)
		}
		return mr.reportLogs, nil
	}
}

// func InstantiateLogsExporter(ctx context.Context, cfg *LogsConfig, log *slog.Logger) (sdklog.Exporter, error) {
// 	var err error
// 	var exporter sdklog.Exporter
// 	switch proto := cfg.GetProtocol(); proto {
// 	case ProtocolHTTPJSON, ProtocolHTTPProtobuf, "": // zero value defaults to HTTP for backwards-compatibility
// 		log.Debug("instantiating HTTP LogsReporter", "protocol", proto)
// 		if exporter, err = httpLogsExporter(ctx, cfg); err != nil {
// 			return nil, fmt.Errorf("can't instantiate OTEL HTTP logs exporter: %w", err)
// 		}
// 	case ProtocolGRPC:
// 		log.Debug("instantiating GRPC LogssReporter", "protocol", proto)
// 		if exporter, err = grpcLogsExporter(ctx, cfg); err != nil {
// 			return nil, fmt.Errorf("can't instantiate OTEL GRPC logs exporter: %w", err)
// 		}
// 	default:
// 		return nil, fmt.Errorf("invalid protocol value: %q. Accepted values are: %s, %s, %s",
// 			proto, ProtocolGRPC, ProtocolHTTPJSON, ProtocolHTTPProtobuf)
// 	}
// 	return exporter, nil
// }

// func httpLogsExporter(ctx context.Context, cfg *LogsConfig) (sdklog.Exporter, error) {
// 	opts, err := getHTTPLogsEndpointOptions(cfg)
// 	if err != nil {
// 		return nil, err
// 	}
// 	mexp, err := otlploghttp.New(ctx, opts.AsLogsHTTP()...)
// 	if err != nil {
// 		return nil, fmt.Errorf("creating HTTP log exporter: %w", err)
// 	}
// 	return mexp, nil
// }

// func grpcLogsExporter(ctx context.Context, cfg *LogsConfig) (sdklog.Exporter, error) {
// 	opts, err := getGRPCLogsEndpointOptions(cfg)
// 	if err != nil {
// 		return nil, err
// 	}
// 	mexp, err := otlploggrpc.New(ctx, opts.AsLogsGRPC()...)
// 	if err != nil {
// 		return nil, fmt.Errorf("creating GRPC log exporter: %w", err)
// 	}
// 	return mexp, nil
// }

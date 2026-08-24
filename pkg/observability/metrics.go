package observability

import (
	"time"
)

// Counter interface for simple incrementing metrics.
type Counter interface {
	Inc()
	Add(float64)
	WithLabelValues(lvs ...string) Counter
}

// Gauge interface for metrics that can go up and down.
type Gauge interface {
	Set(float64)
	Inc()
	Dec()
	WithLabelValues(lvs ...string) Gauge
}

// Histogram interface for measuring distributions.
type Histogram interface {
	Observe(float64)
	WithLabelValues(lvs ...string) Histogram
}

// MetricsRegistry interface for creating new metrics.
type MetricsRegistry interface {
	NewCounter(name, help string) Counter
	NewGauge(name, help string) Gauge
	NewHistogram(name, help string, buckets []float64) Histogram
}

// Metrics holds all metric collectors for the system.
type Metrics struct {
	CNI *CNIMetrics
}

// NewMetrics creates a new Metrics container.
func NewMetrics(registry MetricsRegistry) *Metrics {
	return &Metrics{
		CNI: NewCNIMetrics(registry),
	}
}

// CNIMetrics holds all Prometheus metrics for the CNI plugin.
type CNIMetrics struct {
	PodReadyDuration           Histogram
	PolicyReconcileLag         Histogram
	IPAMBlockUtilization       Gauge
	EBPFMapEntries             Gauge
	ConntrackUtilization       Gauge
	WireGuardHandshakeFailures Counter
	BPFMapWriteErrors          Counter
}

// NewCNIMetrics registers all metrics with the provided registry.
func NewCNIMetrics(registry MetricsRegistry) *CNIMetrics {
	return &CNIMetrics{
		PodReadyDuration: registry.NewHistogram(
			"cni_pod_ready_duration_seconds",
			"Duration of pod readiness stages",
			[]float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10},
		),
		PolicyReconcileLag: registry.NewHistogram(
			"cni_policy_reconcile_lag_seconds",
			"Lag in policy reconciliation",
			[]float64{.01, .05, .1, .5, 1, 2, 5, 10},
		),
		IPAMBlockUtilization: registry.NewGauge(
			"cni_ipam_block_utilization_ratio",
			"Utilization ratio of IPAM blocks",
		),
		EBPFMapEntries: registry.NewGauge(
			"cni_ebpf_map_entries",
			"Number of entries in eBPF maps",
		),
		ConntrackUtilization: registry.NewGauge(
			"cni_conntrack_utilization_ratio",
			"Utilization ratio of conntrack table",
		),
		WireGuardHandshakeFailures: registry.NewCounter(
			"cni_wireguard_handshake_failures_total",
			"Total number of WireGuard handshake failures",
		),
		BPFMapWriteErrors: registry.NewCounter(
			"cni_agent_bpf_map_write_errors_total",
			"Total number of eBPF map write errors",
		),
	}
}

// NoopRegistry implements MetricsRegistry with no-op metrics.
type NoopRegistry struct{}

func NewNoopRegistry() *NoopRegistry {
	return &NoopRegistry{}
}

func (n *NoopRegistry) NewCounter(name, help string) Counter {
	return &noopCounter{}
}

func (n *NoopRegistry) NewGauge(name, help string) Gauge {
	return &noopGauge{}
}

func (n *NoopRegistry) NewHistogram(name, help string, buckets []float64) Histogram {
	return &noopHistogram{}
}

type noopCounter struct{}

func (c *noopCounter) Inc()                                  {}
func (c *noopCounter) Add(float64)                           {}
func (c *noopCounter) WithLabelValues(lvs ...string) Counter { return c }

type noopGauge struct{}

func (g *noopGauge) Set(float64)                         {}
func (g *noopGauge) Inc()                                {}
func (g *noopGauge) Dec()                                {}
func (g *noopGauge) WithLabelValues(lvs ...string) Gauge { return g }

type noopHistogram struct{}

func (h *noopHistogram) Observe(float64)                         {}
func (h *noopHistogram) WithLabelValues(lvs ...string) Histogram { return h }

// StageTimer measures per-stage latency.
type StageTimer struct {
	stage   string
	start   time.Time
	metrics *CNIMetrics
}

// NewStageTimer creates a new timer for a specific CNI stage.
func NewStageTimer(metrics *CNIMetrics, stage string) *StageTimer {
	return &StageTimer{
		stage:   stage,
		start:   time.Now(),
		metrics: metrics,
	}
}

// Done records the elapsed duration for the stage.
func (s *StageTimer) Done() {
	duration := time.Since(s.start).Seconds()
	s.metrics.PodReadyDuration.WithLabelValues(s.stage).Observe(duration)
}

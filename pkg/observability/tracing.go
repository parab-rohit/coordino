package observability

// Tracer interface defines the methods to start spans.
type Tracer interface {
	StartSpan(name string) Span
}

// Span interface defines the methods to manage a single span.
type Span interface {
	End()
	SetAttribute(key, value string)
	SetError(err error)
	AddEvent(name string)
}

// CNITracer is a no-op implementation of the Tracer interface.
type CNITracer struct {
	serviceName string
	enabled     bool
}

// NewCNITracer creates a new CNITracer.
func NewCNITracer(serviceName string, enabled bool) *CNITracer {
	return &CNITracer{
		serviceName: serviceName,
		enabled:     enabled,
	}
}

// StartSpan starts a new no-op span.
func (t *CNITracer) StartSpan(name string) Span {
	return &noopSpan{}
}

type noopSpan struct{}

func (s *noopSpan) End()                           {}
func (s *noopSpan) SetAttribute(key, value string) {}
func (s *noopSpan) SetError(err error)             {}
func (s *noopSpan) AddEvent(name string)           {}

// TracedCNIAdd tracks the 8 stages of the CNI ADD operation.
type TracedCNIAdd struct {
	Parent Span
	Stages map[string]Span
}

// NewTracedCNIAdd creates a new TracedCNIAdd tracker.
func NewTracedCNIAdd(parent Span) *TracedCNIAdd {
	return &TracedCNIAdd{
		Parent: parent,
		Stages: make(map[string]Span),
	}
}

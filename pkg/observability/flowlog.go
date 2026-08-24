package observability

import (
	"fmt"
	"sync"
	"time"
)

// FlowRecord represents a single network flow event.
type FlowRecord struct {
	SrcIdentity   uint32
	DstIdentity   uint32
	SrcIP         string
	DstIP         string
	Proto         uint8
	DstPort       uint16
	Verdict       string
	MatchedPolicy string
	Timestamp     time.Time
}

// FlowExporter defines the interface for exporting flow records.
type FlowExporter interface {
	Export(record FlowRecord) error
	Start() error
	Stop() error
}

// RingBufferExporter implements FlowExporter using an in-memory channel.
type RingBufferExporter struct {
	bufferPath string
	running    bool
	records    chan FlowRecord
	mu         sync.Mutex
}

// NewRingBufferExporter creates a new RingBufferExporter.
func NewRingBufferExporter(bufferPath string, bufSize int) *RingBufferExporter {
	return &RingBufferExporter{
		bufferPath: bufferPath,
		records:    make(chan FlowRecord, bufSize),
	}
}

// Start begins the flow record export process.
func (e *RingBufferExporter) Start() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.running {
		return nil
	}
	e.running = true
	// In a real implementation, a goroutine would read from e.records
	// and write to e.bufferPath.
	go func() {
		for range e.records {
			// Stub: process records
		}
	}()
	return nil
}

// Stop halts the flow record export process.
func (e *RingBufferExporter) Stop() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.running {
		return nil
	}
	e.running = false
	close(e.records)
	return nil
}

// Export sends a flow record to the ring buffer.
func (e *RingBufferExporter) Export(record FlowRecord) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.running {
		return fmt.Errorf("exporter not running")
	}

	// Non-blocking send or drop if full
	select {
	case e.records <- record:
		return nil
	default:
		return fmt.Errorf("buffer full, dropping record")
	}
}

// LogExporter implements FlowExporter by writing records to stdout.
type LogExporter struct {
	running bool
	mu      sync.Mutex
}

// NewLogExporter creates a new LogExporter.
func NewLogExporter() *LogExporter {
	return &LogExporter{}
}

// Start begins the log export process.
func (e *LogExporter) Start() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.running = true
	return nil
}

// Stop halts the log export process.
func (e *LogExporter) Stop() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.running = false
	return nil
}

// Export writes the flow record to stdout.
func (e *LogExporter) Export(record FlowRecord) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.running {
		return fmt.Errorf("exporter not running")
	}
	fmt.Printf("[%s] %s:%d -> %s:%d | %s | %s\n",
		record.Timestamp.Format(time.RFC3339),
		record.SrcIP, record.SrcIdentity,
		record.DstIP, record.DstPort,
		record.Verdict, record.MatchedPolicy)
	return nil
}

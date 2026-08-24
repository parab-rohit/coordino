package policy

import (
	"sync"
)

// PolicyMapKey is the key for the eBPF policy map.
type PolicyMapKey struct {
	SrcIdentity uint32
	DstIdentity uint32
	Proto       uint8
	DstPort     uint16
}

// PolicyMapValue is the value for the eBPF policy map.
type PolicyMapValue struct {
	Verdict  uint8
	AuditLog uint8 // 1=log, 0=silent
}

const (
	MapVerdictAllow uint8 = 1
	MapVerdictDeny  uint8 = 0
)

// MapWriter defines the interface for eBPF map operations.
type MapWriter interface {
	UpdatePolicyMap(key PolicyMapKey, value PolicyMapValue) error
	DeletePolicyMap(key PolicyMapKey) error
	ListPolicyMap() (map[PolicyMapKey]PolicyMapValue, error)
	SyncPolicyMap(desired map[PolicyMapKey]PolicyMapValue) error
}

// EBPFWriter implements MapWriter for eBPF map operations.
type EBPFWriter struct {
	mapPath string
	mu      sync.Mutex
}

// NewEBPFWriter creates a new EBPFWriter.
func NewEBPFWriter(mapPath string) *EBPFWriter {
	return &EBPFWriter{
		mapPath: mapPath,
	}
}

// UpdatePolicyMap updates a single entry in the eBPF policy map.
func (w *EBPFWriter) UpdatePolicyMap(key PolicyMapKey, value PolicyMapValue) error {
	// TODO: Implement actual eBPF map update using cilium/ebpf library
	return nil
}

// DeletePolicyMap deletes a single entry from the eBPF policy map.
func (w *EBPFWriter) DeletePolicyMap(key PolicyMapKey) error {
	// TODO: Implement actual eBPF map delete using cilium/ebpf library
	return nil
}

// ListPolicyMap lists all entries in the eBPF policy map.
func (w *EBPFWriter) ListPolicyMap() (map[PolicyMapKey]PolicyMapValue, error) {
	// TODO: Implement actual eBPF map list using cilium/ebpf library
	return make(map[PolicyMapKey]PolicyMapValue), nil
}

// SyncPolicyMap synchronizes the eBPF map with the desired state.
func (w *EBPFWriter) SyncPolicyMap(desired map[PolicyMapKey]PolicyMapValue) error {
	// TODO: Implement actual eBPF map sync using cilium/ebpf library
	return nil
}

// CompileRulesToMapEntries converts PolicyRules to eBPF map entries.
func (w *EBPFWriter) CompileRulesToMapEntries(rules []PolicyRule) map[PolicyMapKey]PolicyMapValue {
	entries := make(map[PolicyMapKey]PolicyMapValue)
	for _, rule := range rules {
		key := PolicyMapKey{
			SrcIdentity: rule.SrcIdentity,
			DstIdentity: rule.DstIdentity,
			DstPort:     uint16(rule.Port),
		}

		// Map string protocol to uint8
		switch rule.Proto {
		case "tcp":
			key.Proto = 6
		case "udp":
			key.Proto = 17
		case "icmp":
			key.Proto = 1
		default:
			key.Proto = 0 // Any/Unknown
		}

		value := PolicyMapValue{
			AuditLog: 0,
		}
		if rule.Verdict == VerdictAllow {
			value.Verdict = MapVerdictAllow
		} else {
			value.Verdict = MapVerdictDeny
		}

		entries[key] = value
	}
	return entries
}

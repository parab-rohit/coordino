package dataplane

import (
	"net"
	"sync"
)

// LoaderConfig configures the eBPF loader.
type LoaderConfig struct {
	BPFMountPath string // default /sys/fs/bpf
	ProgramDir   string
	PinPath      string
}

// DataPlane defines the internal interface for dataplane operations.
type DataPlane interface {
	Init(config LoaderConfig) error
	LoadPrograms() error
	AttachToExistingMaps() error
	AttachToInterface(ifName string) error
	DetachFromInterface(ifName string) error
	AddPodEndpoint(podIP net.IP, identityID uint32, ifIndex int) error
	RemovePodEndpoint(podIP net.IP) error
	Close() error
	IsHealthy() bool
}

// EBPFDataPlane implements the DataPlane interface using eBPF.
type EBPFDataPlane struct {
	config             LoaderConfig
	loaded             bool
	attachedInterfaces map[string]bool
	mu                 sync.Mutex
}

// NewEBPFDataPlane creates a new EBPFDataPlane instance.
func NewEBPFDataPlane(config LoaderConfig) *EBPFDataPlane {
	return &EBPFDataPlane{
		config:             config,
		attachedInterfaces: make(map[string]bool),
	}
}

// Init initializes the dataplane.
func (e *EBPFDataPlane) Init(config LoaderConfig) error {
	// TODO: Implement cilium/ebpf initialization
	e.config = config
	return nil
}

// LoadPrograms loads eBPF programs into the kernel.
func (e *EBPFDataPlane) LoadPrograms() error {
	// TODO: Implement eBPF program loading
	e.loaded = true
	return nil
}

// AttachToExistingMaps attaches the dataplane to already-pinned maps.
func (e *EBPFDataPlane) AttachToExistingMaps() error {
	// TODO: Implement map attachment for upgrade path
	return nil
}

// AttachToInterface attaches eBPF programs to a network interface.
func (e *EBPFDataPlane) AttachToInterface(ifName string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	// TODO: Implement interface attachment
	e.attachedInterfaces[ifName] = true
	return nil
}

// DetachFromInterface detaches eBPF programs from a network interface.
func (e *EBPFDataPlane) DetachFromInterface(ifName string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	// TODO: Implement interface detachment
	delete(e.attachedInterfaces, ifName)
	return nil
}

// AddPodEndpoint adds a pod endpoint to the dataplane.
func (e *EBPFDataPlane) AddPodEndpoint(podIP net.IP, identityID uint32, ifIndex int) error {
	// TODO: Implement pod endpoint addition (map writes)
	return nil
}

// RemovePodEndpoint removes a pod endpoint from the dataplane.
func (e *EBPFDataPlane) RemovePodEndpoint(podIP net.IP) error {
	// TODO: Implement pod endpoint removal
	return nil
}

// Close closes the dataplane and cleans up resources.
func (e *EBPFDataPlane) Close() error {
	// TODO: Implement cleanup
	return nil
}

// IsHealthy returns true if the dataplane is healthy.
func (e *EBPFDataPlane) IsHealthy() bool {
	return e.loaded
}

// DetectKernelSupport checks if the current kernel supports required eBPF features.
func DetectKernelSupport() (ebpfSupported bool, reason string) {
	// TODO: Implement kernel feature detection
	return true, ""
}

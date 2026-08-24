package dataplane

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"
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

// EndpointEntry represents a pod endpoint.
type EndpointEntry struct {
	PodIP      net.IP
	IdentityID uint32
	IfIndex    int
	MAC        string
	CreatedAt  time.Time
}

// EBPFDataPlane implements the DataPlane interface using eBPF.
type EBPFDataPlane struct {
	config             LoaderConfig
	loaded             bool
	attachedInterfaces map[string]bool
	endpoints          map[string]*EndpointEntry
	identityMap        map[uint32]uint32
	policyEntries      map[string]bool
	programFDs         map[string]int
	mapManager         *MapManager
	mu                 sync.Mutex
}

// NewEBPFDataPlane creates a new EBPFDataPlane instance.
func NewEBPFDataPlane(config LoaderConfig) *EBPFDataPlane {
	return &EBPFDataPlane{
		config:             config,
		attachedInterfaces: make(map[string]bool),
		endpoints:          make(map[string]*EndpointEntry),
		identityMap:        make(map[uint32]uint32),
		policyEntries:      make(map[string]bool),
		programFDs:         make(map[string]int),
		mapManager:         NewMapManager(config.PinPath),
	}
}

// Init initializes the dataplane.
func (e *EBPFDataPlane) Init(config LoaderConfig) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.config = config
	if e.config.BPFMountPath == "" {
		e.config.BPFMountPath = "/sys/fs/bpf"
	}
	return nil
}

// LoadPrograms loads eBPF programs into the kernel.
func (e *EBPFDataPlane) LoadPrograms() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.loaded = true
	e.programFDs["cni_tc_ingress"] = 100
	e.programFDs["cni_tc_egress"] = 101

	for _, m := range DefaultMaps() {
		e.mapManager.EnsureMap(m)
	}
	return nil
}

// AttachToExistingMaps attaches the dataplane to already-pinned maps.
func (e *EBPFDataPlane) AttachToExistingMaps() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.mapManager.RecoverMaps()
}

// AttachToInterface attaches eBPF programs to a network interface.
func (e *EBPFDataPlane) AttachToInterface(ifName string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.attachedInterfaces[ifName] = true
	return nil
}

// DetachFromInterface detaches eBPF programs from a network interface.
func (e *EBPFDataPlane) DetachFromInterface(ifName string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.attachedInterfaces, ifName)
	return nil
}

// AddPodEndpoint adds a pod endpoint to the dataplane.
func (e *EBPFDataPlane) AddPodEndpoint(podIP net.IP, identityID uint32, ifIndex int) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	ip := podIP.To4()
	if ip == nil {
		return fmt.Errorf("only IPv4 supported")
	}

	entry := &EndpointEntry{
		PodIP:      podIP,
		IdentityID: identityID,
		IfIndex:    ifIndex,
		CreatedAt:  time.Now(),
	}
	e.endpoints[podIP.String()] = entry

	ipUint := binary.BigEndian.Uint32(ip)
	e.identityMap[ipUint] = identityID

	// Update identity map
	idVal := make([]byte, 4)
	binary.LittleEndian.PutUint32(idVal, identityID)
	e.mapManager.UpdateMapEntry("identity_map", ip, idVal)

	// Update endpoint map
	// struct endpoint_info { __u32 ifindex; __u32 identity; __u8 mac[6]; };
	epInfo := make([]byte, 16)
	binary.LittleEndian.PutUint32(epInfo[0:4], uint32(ifIndex))
	binary.LittleEndian.PutUint32(epInfo[4:8], identityID)
	// mac at epInfo[8:14]
	e.mapManager.UpdateMapEntry("endpoint_map", ip, epInfo)

	return nil
}

// RemovePodEndpoint removes a pod endpoint from the dataplane.
func (e *EBPFDataPlane) RemovePodEndpoint(podIP net.IP) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	ip := podIP.To4()
	if ip == nil {
		return fmt.Errorf("only IPv4 supported")
	}

	delete(e.endpoints, podIP.String())
	ipUint := binary.BigEndian.Uint32(ip)
	delete(e.identityMap, ipUint)

	e.mapManager.DeleteMapEntry("identity_map", ip)
	e.mapManager.DeleteMapEntry("endpoint_map", ip)

	return nil
}

// Close closes the dataplane and cleans up resources.
func (e *EBPFDataPlane) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.attachedInterfaces = make(map[string]bool)
	e.loaded = false
	return nil
}

// IsHealthy returns true if the dataplane is healthy.
func (e *EBPFDataPlane) IsHealthy() bool {
	return e.loaded
}

// GetEndpoints returns a copy of the endpoints.
func (e *EBPFDataPlane) GetEndpoints() map[string]*EndpointEntry {
	e.mu.Lock()
	defer e.mu.Unlock()
	res := make(map[string]*EndpointEntry)
	for k, v := range e.endpoints {
		res[k] = v
	}
	return res
}

// GetIdentityMap returns the identity mappings.
func (e *EBPFDataPlane) GetIdentityMap() map[uint32]uint32 {
	e.mu.Lock()
	defer e.mu.Unlock()
	res := make(map[uint32]uint32)
	for k, v := range e.identityMap {
		res[k] = v
	}
	return res
}

// UpdateIdentity updates the identity for a pod.
func (e *EBPFDataPlane) UpdateIdentity(podIP net.IP, newIdentityID uint32) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	ip := podIP.To4()
	if ip == nil {
		return fmt.Errorf("only IPv4 supported")
	}

	if entry, ok := e.endpoints[podIP.String()]; ok {
		entry.IdentityID = newIdentityID
	}

	ipUint := binary.BigEndian.Uint32(ip)
	e.identityMap[ipUint] = newIdentityID

	idVal := make([]byte, 4)
	binary.LittleEndian.PutUint32(idVal, newIdentityID)
	return e.mapManager.UpdateMapEntry("identity_map", ip, idVal)
}

// IptablesDataPlane implements DataPlane using iptables as a fallback.
type IptablesDataPlane struct {
	config    LoaderConfig
	chains    map[string][]IptablesRule
	endpoints map[string]*EndpointEntry
	running   bool
	mu        sync.Mutex
}

type IptablesRule struct {
	Chain    string
	Rule     string
	Position int
}

// NewIptablesDataPlane creates a new IptablesDataPlane instance.
func NewIptablesDataPlane(config LoaderConfig) *IptablesDataPlane {
	return &IptablesDataPlane{
		config:    config,
		chains:    make(map[string][]IptablesRule),
		endpoints: make(map[string]*EndpointEntry),
	}
}

func (i *IptablesDataPlane) Init(config LoaderConfig) error {
	i.config = config
	return nil
}

func (i *IptablesDataPlane) LoadPrograms() error {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.running = true
	i.chains["COORDINO-FORWARD"] = []IptablesRule{}
	return nil
}

func (i *IptablesDataPlane) AttachToExistingMaps() error {
	return nil
}

func (i *IptablesDataPlane) AttachToInterface(ifName string) error {
	return nil
}

func (i *IptablesDataPlane) DetachFromInterface(ifName string) error {
	return nil
}

func (i *IptablesDataPlane) AddPodEndpoint(podIP net.IP, identityID uint32, ifIndex int) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.endpoints[podIP.String()] = &EndpointEntry{
		PodIP:      podIP,
		IdentityID: identityID,
		IfIndex:    ifIndex,
		CreatedAt:  time.Now(),
	}
	// Simulate adding iptables rules
	i.chains["COORDINO-FORWARD"] = append(i.chains["COORDINO-FORWARD"], IptablesRule{
		Chain: "COORDINO-FORWARD",
		Rule:  fmt.Sprintf("-s %s -j ACCEPT", podIP.String()),
	})
	return nil
}

func (i *IptablesDataPlane) RemovePodEndpoint(podIP net.IP) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	delete(i.endpoints, podIP.String())
	return nil
}

func (i *IptablesDataPlane) Close() error {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.running = false
	return nil
}

func (i *IptablesDataPlane) IsHealthy() bool {
	return i.running
}

// DetectKernelSupport checks if the current kernel supports required eBPF features.
func DetectKernelSupport() (ebpfSupported bool, reason string) {
	// Check for BPF filesystem mount
	if _, err := os.Stat("/sys/fs/bpf"); err != nil {
		return false, "BPF filesystem not mounted at /sys/fs/bpf"
	}

	// Check kernel version
	data, err := os.ReadFile("/proc/version")
	if err != nil {
		return false, "Could not read /proc/version"
	}
	version := string(data)
	if !strings.Contains(version, "Linux") {
		return false, "Not a Linux kernel"
	}

	// Check for BTF support
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err != nil {
		return false, "BTF not supported by kernel"
	}

	return true, ""
}

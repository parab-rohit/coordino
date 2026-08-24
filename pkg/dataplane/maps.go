package dataplane

import (
	"sync"
)

// MapType defines the type of eBPF map.
type MapType string

const (
	MapTypeIdentity  MapType = "identity"
	MapTypePolicy    MapType = "policy"
	MapTypeConntrack MapType = "conntrack"
	MapTypeEndpoint  MapType = "endpoint"
)

// PinnedMap represents an eBPF map pinned to the filesystem.
type PinnedMap struct {
	Name       string
	Type       MapType
	PinPath    string
	KeySize    int
	ValueSize  int
	MaxEntries int
}

// MapManager manages pinned eBPF maps.
type MapManager struct {
	basePath string
	maps     map[string]*PinnedMap
	mu       sync.RWMutex
}

// NewMapManager creates a new MapManager instance.
func NewMapManager(basePath string) *MapManager {
	return &MapManager{
		basePath: basePath,
		maps:     make(map[string]*PinnedMap),
	}
}

// DefaultMaps returns the standard set of eBPF maps for the dataplane.
func DefaultMaps() []*PinnedMap {
	return []*PinnedMap{
		{
			Name:       "identity_map",
			Type:       MapTypeIdentity,
			PinPath:    "identity_map",
			KeySize:    4, // IPv4 address
			ValueSize:  4, // Identity ID (uint32)
			MaxEntries: 65536,
		},
		{
			Name:       "policy_map",
			Type:       MapTypePolicy,
			PinPath:    "policy_map",
			KeySize:    8, // (src_identity, dst_identity)
			ValueSize:  2, // verdict
			MaxEntries: 65536,
		},
		{
			Name:       "conntrack_map",
			Type:       MapTypeConntrack,
			PinPath:    "conntrack_map",
			KeySize:    20, // 5-tuple
			ValueSize:  16, // state
			MaxEntries: 524288,
		},
		{
			Name:       "endpoint_map",
			Type:       MapTypeEndpoint,
			PinPath:    "endpoint_map",
			KeySize:    4,  // IPv4 address
			ValueSize:  16, // endpoint info
			MaxEntries: 65536,
		},
	}
}

// EnsureMap creates or opens an existing pinned eBPF map.
func (m *MapManager) EnsureMap(pm *PinnedMap) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	// TODO: Implement map creation or opening using cilium/ebpf
	m.maps[pm.Name] = pm
	return nil
}

// DeleteMap unpins and removes an eBPF map.
func (m *MapManager) DeleteMap(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	// TODO: Implement map deletion
	delete(m.maps, name)
	return nil
}

// GetMap returns a registered map by name.
func (m *MapManager) GetMap(name string) (*PinnedMap, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	pm, ok := m.maps[name]
	return pm, ok
}

// RecoverMaps discovers and attaches to already-pinned maps.
func (m *MapManager) RecoverMaps() error {
	// TODO: Implement map discovery for restart/upgrade recovery
	return nil
}

// CleanupStaleMaps removes maps that do not belong to the current configuration.
func (m *MapManager) CleanupStaleMaps() error {
	// TODO: Implement stale map cleanup
	return nil
}

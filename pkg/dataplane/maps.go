package dataplane

import (
	"encoding/hex"
	"fmt"
	"sync"
)

// MapType defines the type of eBPF map.
type MapType string

const (
	MapTypeIdentity  MapType = "identity"
	MapTypePolicy    MapType = "policy"
	MapTypeConntrack MapType = "conntrack"
	MapTypeEndpoint  MapType = "endpoint"
	MapTypeRingBuf   MapType = "ringbuf"
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

// MapStats represents statistics for a map.
type MapStats struct {
	Name        string
	EntryCount  int
	MaxEntries  int
	Utilization float64
}

// MapManager manages pinned eBPF maps.
type MapManager struct {
	basePath string
	maps     map[string]*PinnedMap
	// Simulated map storage: mapName -> hex(key) -> value
	storage map[string]map[string][]byte
	mu      sync.RWMutex
}

// NewMapManager creates a new MapManager instance.
func NewMapManager(basePath string) *MapManager {
	return &MapManager{
		basePath: basePath,
		maps:     make(map[string]*PinnedMap),
		storage:  make(map[string]map[string][]byte),
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
			KeySize:    12, // struct policy_key
			ValueSize:  2,  // struct policy_value
			MaxEntries: 65536,
		},
		{
			Name:       "conntrack_map",
			Type:       MapTypeConntrack,
			PinPath:    "conntrack_map",
			KeySize:    4,
			ValueSize:  4,
			MaxEntries: 65536,
		},
		{
			Name:       "endpoint_map",
			Type:       MapTypeEndpoint,
			PinPath:    "endpoint_map",
			KeySize:    4,  // IPv4 address
			ValueSize:  16, // struct endpoint_info
			MaxEntries: 65536,
		},
	}
}

// EnsureMap creates or opens an existing pinned eBPF map.
func (m *MapManager) EnsureMap(pm *PinnedMap) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.maps[pm.Name] = pm
	if _, ok := m.storage[pm.Name]; !ok {
		m.storage[pm.Name] = make(map[string][]byte)
	}
	return nil
}

// DeleteMap unpins and removes an eBPF map.
func (m *MapManager) DeleteMap(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.maps, name)
	delete(m.storage, name)
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
	m.mu.Lock()
	defer m.mu.Unlock()
	// Simulated recovery: in a real scenario, this would scan the filesystem.
	// For simulation, we assume maps are already "pinned" if they exist in storage.
	return nil
}

// CleanupStaleMaps removes maps that do not belong to the current configuration.
func (m *MapManager) CleanupStaleMaps() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for name := range m.storage {
		if _, ok := m.maps[name]; !ok {
			delete(m.storage, name)
		}
	}
	return nil
}

// UpdateMapEntry writes a value to a map.
func (m *MapManager) UpdateMapEntry(mapName string, key, value []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.storage[mapName]
	if !ok {
		return fmt.Errorf("map %s not found", mapName)
	}
	s[hex.EncodeToString(key)] = value
	return nil
}

// DeleteMapEntry removes a key from a map.
func (m *MapManager) DeleteMapEntry(mapName string, key []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.storage[mapName]
	if !ok {
		return fmt.Errorf("map %s not found", mapName)
	}
	delete(s, hex.EncodeToString(key))
	return nil
}

// LookupMapEntry reads a value from a map.
func (m *MapManager) LookupMapEntry(mapName string, key []byte) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.storage[mapName]
	if !ok {
		return nil, fmt.Errorf("map %s not found", mapName)
	}
	val, ok := s[hex.EncodeToString(key)]
	if !ok {
		return nil, fmt.Errorf("key not found in map %s", mapName)
	}
	return val, nil
}

// GetMapStats returns statistics for all managed maps.
func (m *MapManager) GetMapStats() map[string]MapStats {
	m.mu.RLock()
	defer m.mu.RUnlock()
	stats := make(map[string]MapStats)
	for name, pm := range m.maps {
		count := 0
		if s, ok := m.storage[name]; ok {
			count = len(s)
		}
		util := 0.0
		if pm.MaxEntries > 0 {
			util = float64(count) / float64(pm.MaxEntries)
		}
		stats[name] = MapStats{
			Name:        name,
			EntryCount:  count,
			MaxEntries:  pm.MaxEntries,
			Utilization: util,
		}
	}
	return stats
}

package routing

import (
	"errors"
	"fmt"
	"sync"
)

// VXLANConfig holds VXLAN-specific configuration.
type VXLANConfig struct {
	VNI           int    // VXLAN Network Identifier (default: 1)
	Port          int    // UDP port (default: 4789)
	InterfaceName string // VXLAN interface name (default: "coordino_vxlan")
	MTU           int    // MTU for VXLAN interface (default: 1450, accounting for overhead)
}

// VXLANBackend implements RoutingBackend using VXLAN encapsulation.
type VXLANBackend struct {
	config    VXLANConfig
	localNode NodeInfo
	nodes     map[string]NodeInfo
	fdb       map[string]FDBEntry // forwarding database entries
	routes    map[string]PodRoute
	running   bool
	mu        sync.RWMutex
}

// FDBEntry represents a VXLAN forwarding database entry.
type FDBEntry struct {
	MAC      string
	RemoteIP string
	NodeName string
}

// NewVXLANBackend creates a new VXLAN routing backend.
func NewVXLANBackend(config VXLANConfig) *VXLANBackend {
	if config.VNI == 0 {
		config.VNI = 1
	}
	if config.Port == 0 {
		config.Port = 4789
	}
	if config.InterfaceName == "" {
		config.InterfaceName = "coordino_vxlan"
	}
	if config.MTU == 0 {
		config.MTU = 1450
	}
	return &VXLANBackend{
		config: config,
		nodes:  make(map[string]NodeInfo),
		fdb:    make(map[string]FDBEntry),
		routes: make(map[string]PodRoute),
	}
}

// Init initializes the routing backend.
func (v *VXLANBackend) Init(localNode NodeInfo) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.localNode = localNode
	err := v.EnsureVXLANInterface()
	if err != nil {
		return err
	}
	v.running = true
	return nil
}

// AddNode adds FDB entry for remote node, add route via VXLAN interface.
func (v *VXLANBackend) AddNode(node NodeInfo) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if !v.running {
		return errors.New("VXLAN backend not running")
	}

	v.nodes[node.Name] = node

	// Simulating MAC generation for the node
	// In a real implementation, this might be derived from the NodeIP or exchanged
	mac := fmt.Sprintf("00:00:5e:00:53:%02x", len(v.nodes))

	v.fdb[node.Name] = FDBEntry{
		MAC:      mac,
		RemoteIP: node.NodeIP,
		NodeName: node.Name,
	}

	v.routes[node.PodCIDR] = PodRoute{
		DestCIDR:  node.PodCIDR,
		NextHop:   node.NodeIP,
		NodeName:  node.Name,
		Interface: v.config.InterfaceName,
	}

	// TODO: Implement netlink calls to add FDB entry and route
	return nil
}

// RemoveNode removes FDB entry and routes.
func (v *VXLANBackend) RemoveNode(nodeName string) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	node, exists := v.nodes[nodeName]
	if !exists {
		return nil
	}

	delete(v.routes, node.PodCIDR)
	delete(v.fdb, nodeName)
	delete(v.nodes, nodeName)

	// TODO: Implement netlink calls to remove FDB entry and route
	return nil
}

// UpdateNode updates FDB and routes.
func (v *VXLANBackend) UpdateNode(node NodeInfo) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	if oldNode, exists := v.nodes[node.Name]; exists {
		delete(v.routes, oldNode.PodCIDR)
	}

	v.nodes[node.Name] = node

	mac := fmt.Sprintf("00:00:5e:00:53:%02x", len(v.nodes))
	v.fdb[node.Name] = FDBEntry{
		MAC:      mac,
		RemoteIP: node.NodeIP,
		NodeName: node.Name,
	}

	v.routes[node.PodCIDR] = PodRoute{
		DestCIDR:  node.PodCIDR,
		NextHop:   node.NodeIP,
		NodeName:  node.Name,
		Interface: v.config.InterfaceName,
	}

	// TODO: Implement netlink calls to update FDB entry and route
	return nil
}

// SyncRoutes full reconciliation of FDB + routes.
func (v *VXLANBackend) SyncRoutes(nodes []NodeInfo) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	newNodeMap := make(map[string]NodeInfo)
	for _, node := range nodes {
		if node.Name == v.localNode.Name {
			continue
		}
		newNodeMap[node.Name] = node
	}

	// Remove stale
	for name, node := range v.nodes {
		if _, exists := newNodeMap[name]; !exists {
			delete(v.routes, node.PodCIDR)
			delete(v.fdb, name)
			delete(v.nodes, name)
		}
	}

	// Add or update
	for name, node := range newNodeMap {
		v.nodes[name] = node
		mac := fmt.Sprintf("00:00:5e:00:53:%02x", len(v.nodes))
		v.fdb[name] = FDBEntry{
			MAC:      mac,
			RemoteIP: node.NodeIP,
			NodeName: name,
		}
		v.routes[node.PodCIDR] = PodRoute{
			DestCIDR:  node.PodCIDR,
			NextHop:   node.NodeIP,
			NodeName:  name,
			Interface: v.config.InterfaceName,
		}
	}

	// TODO: Reconcile with actual OS state using netlink
	return nil
}

// GetRoutes return routes.
func (v *VXLANBackend) GetRoutes() ([]PodRoute, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	routes := make([]PodRoute, 0, len(v.routes))
	for _, r := range v.routes {
		routes = append(routes, r)
	}
	return routes, nil
}

// Close tear down VXLAN interface.
func (v *VXLANBackend) Close() error {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.running = false
	// TODO: Netlink call to delete VXLAN interface
	return nil
}

// Mode return ModeVXLAN.
func (v *VXLANBackend) Mode() Mode {
	return ModeVXLAN
}

// IsHealthy check VXLAN interface exists.
func (v *VXLANBackend) IsHealthy() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	// In a real implementation, we would check if the interface actually exists in the OS.
	return v.running
}

// GetFDB returns all FDB entries.
func (v *VXLANBackend) GetFDB() map[string]FDBEntry {
	v.mu.RLock()
	defer v.mu.RUnlock()

	fdb := make(map[string]FDBEntry)
	for k, entry := range v.fdb {
		fdb[k] = entry
	}
	return fdb
}

// EnsureVXLANInterface creates or verifies the VXLAN interface.
func (v *VXLANBackend) EnsureVXLANInterface() error {
	// TODO: Implement netlink logic to create/verify VXLAN interface
	// e.g., ip link add coordino_vxlan type vxlan id 1 dstport 4789 dev eth0
	return nil
}

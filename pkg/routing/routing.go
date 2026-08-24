package routing

import (
	"fmt"
)

// Mode defines the routing backend type.
type Mode string

const (
	ModeBGP      Mode = "bgp"
	ModeVXLAN    Mode = "vxlan"
	ModeCloudVPC Mode = "cloud-vpc"
)

// PodRoute represents a route to a pod CIDR on a specific node.
type PodRoute struct {
	DestCIDR  string // e.g., "10.0.1.0/24"
	NextHop   string // next-hop IP for the route
	NodeName  string // target node
	Interface string // outgoing interface
}

// NodeInfo holds routing-relevant information about a cluster node.
type NodeInfo struct {
	Name     string
	PodCIDR  string
	NodeIP   string
	PublicIP string // for cloud environments
}

// RoutingBackend defines the strategy interface for routing backends.
// All routing modes implement this interface.
type RoutingBackend interface {
	// Init initializes the routing backend.
	Init(localNode NodeInfo) error

	// AddNode adds routes for a new node's pod CIDR.
	AddNode(node NodeInfo) error

	// RemoveNode removes routes for a departing node.
	RemoveNode(nodeName string) error

	// UpdateNode updates routes when a node's info changes.
	UpdateNode(node NodeInfo) error

	// SyncRoutes reconciles the routing table with the desired state.
	SyncRoutes(nodes []NodeInfo) error

	// GetRoutes returns all currently installed routes.
	GetRoutes() ([]PodRoute, error)

	// Close shuts down the routing backend.
	Close() error

	// Mode returns the routing mode.
	Mode() Mode

	// IsHealthy returns true if the backend is operating normally.
	IsHealthy() bool
}

// NewRoutingBackend creates a routing backend based on the specified mode.
func NewRoutingBackend(mode Mode, config map[string]string) (RoutingBackend, error) {
	switch mode {
	case ModeBGP:
		// In a real implementation, we would parse BGPConfig from the config map.
		// For now, we return a new BGP backend with default config.
		return NewBGPBackend(BGPConfig{}), nil
	case ModeVXLAN:
		// In a real implementation, we would parse VXLANConfig from the config map.
		// For now, we return a new VXLAN backend with default config.
		return NewVXLANBackend(VXLANConfig{}), nil
	default:
		return nil, fmt.Errorf("unsupported routing mode: %s", mode)
	}
}

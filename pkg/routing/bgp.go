package routing

import (
	"errors"
	"sync"
	"time"
)

// BGPConfig holds BGP-specific configuration.
type BGPConfig struct {
	LocalASN    uint32
	RouterID    string
	PeerASN     uint32
	PeerAddress string
	HoldTime    int // seconds
}

// BGPBackend implements RoutingBackend using BGP route distribution.
type BGPBackend struct {
	config    BGPConfig
	localNode NodeInfo
	peers     map[string]*BGPPeer
	routes    map[string]PodRoute // keyed by destCIDR
	running   bool
	mu        sync.RWMutex
}

// BGPPeer represents a BGP peer (another node).
type BGPPeer struct {
	NodeInfo NodeInfo
	State    string // "Idle", "Connect", "Active", "OpenSent", "OpenConfirm", "Established"
	Uptime   time.Time
	RoutesRx int
	RoutesTx int
}

// NewBGPBackend creates a new BGP routing backend.
func NewBGPBackend(config BGPConfig) *BGPBackend {
	return &BGPBackend{
		config: config,
		peers:  make(map[string]*BGPPeer),
		routes: make(map[string]PodRoute),
	}
}

// Init initializes the routing backend.
func (b *BGPBackend) Init(localNode NodeInfo) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.localNode = localNode
	b.running = true
	// TODO: Initialize local BGP speaker speaker process (e.g., GoBGP)
	return nil
}

// AddNode adds BGP peer for the node, install route for the node's pod CIDR.
func (b *BGPBackend) AddNode(node NodeInfo) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.running {
		return errors.New("BGP backend not running")
	}

	peer := &BGPPeer{
		NodeInfo: node,
		State:    "Established", // Simulating established state for demonstration
		Uptime:   time.Now(),
	}
	b.peers[node.Name] = peer

	route := PodRoute{
		DestCIDR: node.PodCIDR,
		NextHop:  node.NodeIP,
		NodeName: node.Name,
	}
	b.routes[node.PodCIDR] = route

	// TODO: Send BGP Update message to all peers via the BGP speaker
	return nil
}

// RemoveNode removes BGP peer and associated routes.
func (b *BGPBackend) RemoveNode(nodeName string) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	peer, exists := b.peers[nodeName]
	if !exists {
		return nil
	}

	delete(b.routes, peer.NodeInfo.PodCIDR)
	delete(b.peers, nodeName)

	// TODO: Send BGP Withdraw message to all peers via the BGP speaker
	return nil
}

// UpdateNode updates peer info and routes.
func (b *BGPBackend) UpdateNode(node NodeInfo) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	oldPeer, exists := b.peers[node.Name]
	if exists {
		delete(b.routes, oldPeer.NodeInfo.PodCIDR)
	}

	peer := &BGPPeer{
		NodeInfo: node,
		State:    "Established",
		Uptime:   time.Now(),
	}
	b.peers[node.Name] = peer

	route := PodRoute{
		DestCIDR: node.PodCIDR,
		NextHop:  node.NodeIP,
		NodeName: node.Name,
	}
	b.routes[node.PodCIDR] = route

	// TODO: Update BGP peer configuration and re-advertise routes if needed
	return nil
}

// SyncRoutes reconciles desired vs actual routes, add missing, remove stale.
func (b *BGPBackend) SyncRoutes(nodes []NodeInfo) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	newNodeMap := make(map[string]NodeInfo)
	for _, node := range nodes {
		if node.Name == b.localNode.Name {
			continue
		}
		newNodeMap[node.Name] = node
	}

	// Remove stale peers and routes
	for name, peer := range b.peers {
		if _, exists := newNodeMap[name]; !exists {
			delete(b.routes, peer.NodeInfo.PodCIDR)
			delete(b.peers, name)
		}
	}

	// Add or update peers and routes
	for name, node := range newNodeMap {
		peer := &BGPPeer{
			NodeInfo: node,
			State:    "Established",
			Uptime:   time.Now(),
		}
		b.peers[name] = peer

		route := PodRoute{
			DestCIDR: node.PodCIDR,
			NextHop:  node.NodeIP,
			NodeName: node.Name,
		}
		b.routes[node.PodCIDR] = route
	}

	return nil
}

// GetRoutes returns a copy of the current routes.
func (b *BGPBackend) GetRoutes() ([]PodRoute, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	routes := make([]PodRoute, 0, len(b.routes))
	for _, r := range b.routes {
		routes = append(routes, r)
	}
	return routes, nil
}

// Close shuts down all peers.
func (b *BGPBackend) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.running = false
	b.peers = make(map[string]*BGPPeer)
	b.routes = make(map[string]PodRoute)
	// TODO: Shut down local BGP speaker speaker process
	return nil
}

// Mode returns ModeBGP.
func (b *BGPBackend) Mode() Mode {
	return ModeBGP
}

// IsHealthy returns true if the backend is operating normally.
func (b *BGPBackend) IsHealthy() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if !b.running {
		return false
	}
	// Healthy if at least one peer is Established
	for _, peer := range b.peers {
		if peer.State == "Established" {
			return true
		}
	}
	return false
}

// GetPeerStatus returns status info for all BGP peers.
func (b *BGPBackend) GetPeerStatus() map[string]*BGPPeer {
	b.mu.RLock()
	defer b.mu.RUnlock()

	status := make(map[string]*BGPPeer)
	for k, v := range b.peers {
		// Return copy of the peer info
		peerCopy := *v
		status[k] = &peerCopy
	}
	return status
}

// AdvertiseRoute advertises a route to all BGP peers.
func (b *BGPBackend) AdvertiseRoute(route PodRoute) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.running {
		return errors.New("BGP backend not running")
	}
	b.routes[route.DestCIDR] = route
	// TODO: Implement actual BGP advertisement logic via BGP speaker
	return nil
}

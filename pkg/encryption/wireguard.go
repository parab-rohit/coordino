package encryption

import (
	"sync"
	"time"
)

// WireGuardConfig defines the configuration for the WireGuard interface.
type WireGuardConfig struct {
	InterfaceName  string
	ListenPort     int
	PrivateKeyPath string
	MTU            int
}

// Peer represents a WireGuard peer node.
type Peer struct {
	PublicKey     string
	Endpoint      string
	AllowedIPs    []string
	NodeName      string
	LastHandshake time.Time
}

// KeyPair holds a WireGuard private and public key pair.
type KeyPair struct {
	PrivateKey  string
	PublicKey   string
	GeneratedAt time.Time
}

// EncryptionScope defines the scope of WireGuard encryption.
type EncryptionScope string

const (
	ScopeClusterWide  EncryptionScope = "ClusterWide"
	ScopePerNamespace EncryptionScope = "PerNamespace"
	ScopeDisabled     EncryptionScope = "Disabled"
)

// Manager handles WireGuard encryption-in-transit.
type Manager struct {
	config  WireGuardConfig
	keyPair *KeyPair
	peers   map[string]*Peer
	scope   EncryptionScope
	mu      sync.RWMutex
}

// NewManager creates a new WireGuard manager.
func NewManager(config WireGuardConfig) *Manager {
	if config.InterfaceName == "" {
		config.InterfaceName = "wg0"
	}
	if config.ListenPort == 0 {
		config.ListenPort = 51820
	}
	return &Manager{
		config: config,
		peers:  make(map[string]*Peer),
		scope:  ScopeDisabled,
	}
}

// GenerateKeyPair generates a new WireGuard keypair.
func GenerateKeyPair() (*KeyPair, error) {
	// TODO: Requires wireguard-go or wg command to generate actual keys.
	return &KeyPair{
		PrivateKey:  "stub-private-key",
		PublicKey:   "stub-public-key",
		GeneratedAt: time.Now(),
	}, nil
}

// SetKeyPair sets the local node's key pair.
func (m *Manager) SetKeyPair(kp *KeyPair) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.keyPair = kp
}

// GetPublicKey returns the current public key.
func (m *Manager) GetPublicKey() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.keyPair == nil {
		return ""
	}
	return m.keyPair.PublicKey
}

// AddPeer adds or updates a WireGuard peer.
func (m *Manager) AddPeer(peer *Peer) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// TODO: Implement actual WireGuard peer configuration using Netlink or wg command.
	m.peers[peer.NodeName] = peer
	return nil
}

// RemovePeer removes a WireGuard peer by node name.
func (m *Manager) RemovePeer(nodeName string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// TODO: Implement actual WireGuard peer removal.
	delete(m.peers, nodeName)
	return nil
}

// ProvisionAllPeers bulk provisions all peers at startup.
func (m *Manager) ProvisionAllPeers(peers []*Peer) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// TODO: Implement bulk WireGuard peer configuration.
	for _, p := range peers {
		m.peers[p.NodeName] = p
	}
	return nil
}

// SetScope sets the encryption toggle.
func (m *Manager) SetScope(scope EncryptionScope) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.scope = scope
}

// GetScope returns the current encryption scope.
func (m *Manager) GetScope() EncryptionScope {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.scope
}

// IsEnabled returns true if encryption is not disabled.
func (m *Manager) IsEnabled() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.scope != ScopeDisabled
}

// RotateKeys generates a new keypair and prepares for rotation.
func (m *Manager) RotateKeys() (*KeyPair, error) {
	// TODO: Implement key rotation logic.
	kp, err := GenerateKeyPair()
	if err != nil {
		return nil, err
	}
	// Rotation logic would involve updating the interface and notifying peers via CRD.
	return kp, nil
}

// GetPeerStatus returns a copy of the current peers with their status.
func (m *Manager) GetPeerStatus() map[string]*Peer {
	m.mu.RLock()
	defer m.mu.RUnlock()

	status := make(map[string]*Peer)
	for k, v := range m.peers {
		// Return a shallow copy of the peer struct
		p := *v
		status[k] = &p
	}
	return status
}

// InterfaceExists checks if the WireGuard interface exists.
func (m *Manager) InterfaceExists() bool {
	// TODO: Implement check using net.InterfaceByName or similar.
	return false
}

// EnsureInterface creates the WireGuard interface if it does not exist.
func (m *Manager) EnsureInterface() error {
	// TODO: Implement interface creation using Netlink or wg command.
	return nil
}

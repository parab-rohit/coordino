package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"sync"
)

// Identity represents a Cilium-style security identity.
type Identity struct {
	ID        uint32
	Labels    map[string]string
	LabelHash string
	RefCount  int
	Nodes     map[string]bool
}

// IdentityAllocator manages the allocation and lifecycle of security identities.
type IdentityAllocator struct {
	identities map[uint32]*Identity
	hashToID   map[string]uint32
	nextID     uint32
	mu         sync.RWMutex
}

// NewIdentityAllocator creates a new IdentityAllocator.
func NewIdentityAllocator() *IdentityAllocator {
	return &IdentityAllocator{
		identities: make(map[uint32]*Identity),
		hashToID:   make(map[string]uint32),
		nextID:     1,
	}
}

// AllocateIdentity hashes labels, reuses existing identity or assigns a new ID.
func (a *IdentityAllocator) AllocateIdentity(labels map[string]string) (*Identity, error) {
	hash := a.hashLabels(labels)

	a.mu.Lock()
	defer a.mu.Unlock()

	if id, exists := a.hashToID[hash]; exists {
		identity := a.identities[id]
		identity.RefCount++
		return identity, nil
	}

	id := a.nextID
	a.nextID++

	identity := &Identity{
		ID:        id,
		Labels:    labels,
		LabelHash: hash,
		RefCount:  1,
		Nodes:     make(map[string]bool),
	}

	a.identities[id] = identity
	a.hashToID[hash] = id

	return identity, nil
}

// ReleaseIdentity decrements the ref count and garbage collects the identity when it reaches 0.
func (a *IdentityAllocator) ReleaseIdentity(id uint32) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	identity, exists := a.identities[id]
	if !exists {
		return fmt.Errorf("identity %d not found", id)
	}

	identity.RefCount--
	if identity.RefCount <= 0 {
		delete(a.hashToID, identity.LabelHash)
		delete(a.identities, id)
	}

	return nil
}

// GetIdentity returns an identity by its ID.
func (a *IdentityAllocator) GetIdentity(id uint32) (*Identity, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	identity, exists := a.identities[id]
	return identity, exists
}

// GetIdentityByLabels returns an identity by its labels.
func (a *IdentityAllocator) GetIdentityByLabels(labels map[string]string) (*Identity, bool) {
	hash := a.hashLabels(labels)

	a.mu.RLock()
	defer a.mu.RUnlock()

	id, exists := a.hashToID[hash]
	if !exists {
		return nil, false
	}
	return a.identities[id], true
}

// GetIdentitiesForNode returns all identities currently present on a node.
func (a *IdentityAllocator) GetIdentitiesForNode(nodeName string) []*Identity {
	a.mu.RLock()
	defer a.mu.RUnlock()

	var result []*Identity
	for _, identity := range a.identities {
		if identity.Nodes[nodeName] {
			result = append(result, identity)
		}
	}
	return result
}

// AddNodeReference adds a node reference to an identity.
func (a *IdentityAllocator) AddNodeReference(id uint32, nodeName string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	identity, exists := a.identities[id]
	if !exists {
		return fmt.Errorf("identity %d not found", id)
	}

	identity.Nodes[nodeName] = true
	return nil
}

// RemoveNodeReference removes a node reference from an identity.
func (a *IdentityAllocator) RemoveNodeReference(id uint32, nodeName string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	identity, exists := a.identities[id]
	if !exists {
		return fmt.Errorf("identity %d not found", id)
	}

	delete(identity.Nodes, nodeName)
	return nil
}

// hashLabels generates a deterministic sha256 hash for a set of labels.
func (a *IdentityAllocator) hashLabels(labels map[string]string) string {
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var sb strings.Builder
	for _, k := range keys {
		sb.WriteString(k)
		sb.WriteString("=")
		sb.WriteString(labels[k])
		sb.WriteString(";")
	}
	h := sha256.New()
	h.Write([]byte(sb.String()))
	return hex.EncodeToString(h.Sum(nil))
}

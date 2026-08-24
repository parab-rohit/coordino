package ipam

import (
	"fmt"
	"net"
	"sync"
	"time"
)

// allocRecord tracks an assigned IP address.
type allocRecord struct {
	IP           net.IP
	PodName      string
	PodNamespace string
	AllocatedAt  time.Time
}

// NodeAllocator manages IP allocation for a single node using a bitmap.
type NodeAllocator struct {
	PodCIDR   *net.IPNet
	bitmap    []bool
	allocated map[string]allocRecord // key: "podName/podNamespace"
	mu        sync.RWMutex
	baseIP    net.IP
	blockSize int
}

// NewNodeAllocator creates a new NodeAllocator for the given pod CIDR.
func NewNodeAllocator(podCIDR string) (*NodeAllocator, error) {
	_, ipnet, err := net.ParseCIDR(podCIDR)
	if err != nil {
		return nil, fmt.Errorf("invalid pod CIDR: %w", err)
	}

	ones, bits := ipnet.Mask.Size()
	size := 1 << (bits - ones)

	return &NodeAllocator{
		PodCIDR:   ipnet,
		bitmap:    make([]bool, size),
		allocated: make(map[string]allocRecord),
		baseIP:    ipnet.IP,
		blockSize: size,
	}, nil
}

// Allocate finds the first free IP in the block and assigns it to the pod.
func (a *NodeAllocator) Allocate(podName, podNamespace string) (net.IP, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	key := fmt.Sprintf("%s/%s", podName, podNamespace)
	if record, exists := a.allocated[key]; exists {
		return record.IP, nil
	}

	for i := 0; i < a.blockSize; i++ {
		// Skip network and broadcast addresses
		if i == 0 || i == a.blockSize-1 {
			continue
		}

		if !a.bitmap[i] {
			ip := uint32ToIP(ipToUint32(a.baseIP) + uint32(i))

			a.bitmap[i] = true
			a.allocated[key] = allocRecord{
				IP:           ip,
				PodName:      podName,
				PodNamespace: podNamespace,
				AllocatedAt:  time.Now(),
			}
			return ip, nil
		}
	}

	return nil, fmt.Errorf("no available IPs in block %s", a.PodCIDR)
}

// Release frees the IP address associated with the pod identity.
func (a *NodeAllocator) Release(podName, podNamespace string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	key := fmt.Sprintf("%s/%s", podName, podNamespace)
	record, exists := a.allocated[key]
	if !exists {
		return nil
	}

	offset := int(ipToUint32(record.IP) - ipToUint32(a.baseIP))
	if offset >= 0 && offset < a.blockSize {
		a.bitmap[offset] = false
	}
	delete(a.allocated, key)

	return nil
}

// IsAllocated checks if the given IP is currently allocated.
func (a *NodeAllocator) IsAllocated(ip net.IP) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()

	for _, record := range a.allocated {
		if record.IP.Equal(ip) {
			return true
		}
	}
	return false
}

// GetAllocatedIPs returns a copy of the current allocations.
func (a *NodeAllocator) GetAllocatedIPs() map[string]net.IP {
	a.mu.RLock()
	defer a.mu.RUnlock()

	res := make(map[string]net.IP)
	for key, record := range a.allocated {
		res[key] = record.IP
	}
	return res
}

// Reconcile releases IPs for pods that are no longer in the active set.
func (a *NodeAllocator) Reconcile(activePods map[string]bool) (released []net.IP) {
	a.mu.Lock()
	defer a.mu.Unlock()

	for key, record := range a.allocated {
		if !activePods[key] {
			offset := int(ipToUint32(record.IP) - ipToUint32(a.baseIP))
			if offset >= 0 && offset < a.blockSize {
				a.bitmap[offset] = false
			}
			released = append(released, record.IP)
			delete(a.allocated, key)
		}
	}
	return released
}

// Utilization returns the ratio of allocated IPs to total usable IPs.
func (a *NodeAllocator) Utilization() float64 {
	a.mu.RLock()
	defer a.mu.RUnlock()

	if a.blockSize <= 2 {
		return 1.0
	}
	return float64(len(a.allocated)) / float64(a.blockSize-2)
}

// Available returns the count of free usable IPs.
func (a *NodeAllocator) Available() int {
	a.mu.RLock()
	defer a.mu.RUnlock()

	count := 0
	for i := 1; i < a.blockSize-1; i++ {
		if !a.bitmap[i] {
			count++
		}
	}
	return count
}

func ipToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

func uint32ToIP(v uint32) net.IP {
	return net.IPv4(byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

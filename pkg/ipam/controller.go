package ipam

import (
	"fmt"
	"net"
	"sync"
	"time"
)

// BlockAssignment tracks a CIDR block assigned to a node.
type BlockAssignment struct {
	NodeName    string
	CIDR        *net.IPNet
	AllocatedAt time.Time
}

// IPAMController manages IP block allocation across the cluster.
type IPAMController struct {
	ClusterCIDR    *net.IPNet
	BlockSize      int
	assignments    map[string][]*BlockAssignment
	nextBlockIndex int
	mu             sync.RWMutex
}

// NewIPAMController creates a new IPAMController.
func NewIPAMController(clusterCIDR string, blockSize int) (*IPAMController, error) {
	_, ipnet, err := net.ParseCIDR(clusterCIDR)
	if err != nil {
		return nil, fmt.Errorf("invalid cluster CIDR: %w", err)
	}

	return &IPAMController{
		ClusterCIDR: ipnet,
		BlockSize:   blockSize,
		assignments: make(map[string][]*BlockAssignment),
	}, nil
}

// AssignBlock assigns the next available block to a node.
func (c *IPAMController) AssignBlock(nodeName string) (*net.IPNet, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if blocks, exists := c.assignments[nodeName]; exists && len(blocks) > 0 {
		return blocks[0].CIDR, nil
	}

	return c.assignNextBlock(nodeName)
}

func (c *IPAMController) assignNextBlock(nodeName string) (*net.IPNet, error) {
	ones, bits := c.ClusterCIDR.Mask.Size()
	totalBlocks := 1 << (c.BlockSize - ones)

	if c.nextBlockIndex >= totalBlocks {
		return nil, fmt.Errorf("no more blocks available in cluster CIDR %s", c.ClusterCIDR)
	}

	baseIP := ipToUint32(c.ClusterCIDR.IP)
	blockIPVal := baseIP + uint32(c.nextBlockIndex)<<uint32(bits-c.BlockSize)
	blockIP := uint32ToIP(blockIPVal)

	blockCIDR := &net.IPNet{
		IP:   blockIP,
		Mask: net.CIDRMask(c.BlockSize, bits),
	}

	assignment := &BlockAssignment{
		NodeName:    nodeName,
		CIDR:        blockCIDR,
		AllocatedAt: time.Now(),
	}

	c.assignments[nodeName] = append(c.assignments[nodeName], assignment)
	c.nextBlockIndex++

	return blockCIDR, nil
}

// AssignSecondaryBlock assigns an additional block for overflow.
func (c *IPAMController) AssignSecondaryBlock(nodeName string) (*net.IPNet, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.assignNextBlock(nodeName)
}

// ReleaseBlocks releases all blocks assigned to a node.
func (c *IPAMController) ReleaseBlocks(nodeName string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.assignments, nodeName)
	return nil
}

// GetAssignment returns the blocks assigned to a node.
func (c *IPAMController) GetAssignment(nodeName string) ([]*BlockAssignment, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	blocks, exists := c.assignments[nodeName]
	if !exists {
		return nil, fmt.Errorf("no assignment found for node %s", nodeName)
	}
	return blocks, nil
}

// GetAllAssignments returns all node-to-block assignments.
func (c *IPAMController) GetAllAssignments() map[string][]*BlockAssignment {
	c.mu.RLock()
	defer c.mu.RUnlock()

	res := make(map[string][]*BlockAssignment)
	for k, v := range c.assignments {
		res[k] = v
	}
	return res
}

// IsBlockAvailable checks if there are any blocks left in the cluster CIDR.
func (c *IPAMController) IsBlockAvailable() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	ones, _ := c.ClusterCIDR.Mask.Size()
	totalBlocks := 1 << (c.BlockSize - ones)
	return c.nextBlockIndex < totalBlocks
}

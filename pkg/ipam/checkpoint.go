package ipam

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// CheckpointRecord represents a single IP allocation record for persistence.
type CheckpointRecord struct {
	PodName      string    `json:"podName"`
	PodNamespace string    `json:"podNamespace"`
	IP           string    `json:"ip"`
	AllocatedAt  time.Time `json:"allocatedAt"`
}

// Checkpoint represents the full checkpoint state.
type Checkpoint struct {
	PodCIDR   string             `json:"podCIDR"`
	Records   []CheckpointRecord `json:"records"`
	Timestamp time.Time          `json:"timestamp"`
	Version   int                `json:"version"`
}

// CheckpointManager handles reading/writing checkpoint files.
type CheckpointManager struct {
	path string
	mu   sync.Mutex
}

// NewCheckpointManager creates a new CheckpointManager.
func NewCheckpointManager(path string) *CheckpointManager {
	return &CheckpointManager{
		path: path,
	}
}

// Save atomically writes the checkpoint to the file.
func (m *CheckpointManager) Save(allocator *NodeAllocator) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// 1. Get current allocations from allocator via GetAllocatedIPs()
	allocations := allocator.GetAllocatedIPs()

	// 2. Create Checkpoint struct with all records
	var records []CheckpointRecord
	for key, ip := range allocations {
		parts := strings.SplitN(key, "/", 2)
		podName := parts[0]
		podNamespace := ""
		if len(parts) > 1 {
			podNamespace = parts[1]
		}

		records = append(records, CheckpointRecord{
			PodName:      podName,
			PodNamespace: podNamespace,
			IP:           ip.String(),
			AllocatedAt:  time.Now(),
		})
	}

	checkpoint := Checkpoint{
		PodCIDR:   allocator.PodCIDR.String(),
		Records:   records,
		Timestamp: time.Now(),
		Version:   1,
	}

	// 3. Marshal to JSON
	data, err := json.MarshalIndent(checkpoint, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal checkpoint: %w", err)
	}

	// 4. Write to a temp file (path + ".tmp")
	tmpPath := m.path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write temp checkpoint file: %w", err)
	}

	// 5. Rename temp to final path
	if err := os.Rename(tmpPath, m.path); err != nil {
		return fmt.Errorf("failed to rename temp checkpoint file: %w", err)
	}

	return nil
}

// Load reads and parses the checkpoint file.
func (m *CheckpointManager) Load() (*Checkpoint, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	data, err := os.ReadFile(m.path)
	if err != nil {
		return nil, fmt.Errorf("failed to read checkpoint file: %w", err)
	}

	var checkpoint Checkpoint
	if err := json.Unmarshal(data, &checkpoint); err != nil {
		return nil, fmt.Errorf("failed to unmarshal checkpoint: %w", err)
	}

	return &checkpoint, nil
}

// Restore restores allocator state from a checkpoint.
func (m *CheckpointManager) Restore(allocator *NodeAllocator, checkpoint *Checkpoint) error {
	for _, record := range checkpoint.Records {
		// 1. For each record in checkpoint, call allocator.Allocate(podName, podNamespace)
		allocatedIP, err := allocator.Allocate(record.PodName, record.PodNamespace)
		if err != nil {
			return fmt.Errorf("failed to restore allocation for %s/%s: %w", record.PodNamespace, record.PodName, err)
		}

		// 2. If the allocated IP doesn't match the checkpointed IP, log a warning but continue
		if allocatedIP.String() != record.IP {
			fmt.Printf("WARNING: Restored IP %s for pod %s/%s does not match checkpointed IP %s\n",
				allocatedIP.String(), record.PodNamespace, record.PodName, record.IP)
		}
	}

	return nil
}

// Exists checks if the checkpoint file exists.
func (m *CheckpointManager) Exists() bool {
	_, err := os.Stat(m.path)
	return err == nil
}

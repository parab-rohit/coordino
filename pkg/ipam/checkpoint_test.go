package ipam

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCheckpointSaveLoad(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "checkpoint-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	checkpointPath := filepath.Join(tmpDir, "checkpoint.json")
	mgr := NewCheckpointManager(checkpointPath)

	allocator, err := NewNodeAllocator("10.0.0.0/24")
	if err != nil {
		t.Fatalf("failed to create allocator: %v", err)
	}

	pod1Name, pod1NS := "pod1", "ns1"
	ip1, err := allocator.Allocate(pod1Name, pod1NS)
	if err != nil {
		t.Fatalf("failed to allocate IP 1: %v", err)
	}

	pod2Name, pod2NS := "pod2", "ns2"
	ip2, err := allocator.Allocate(pod2Name, pod2NS)
	if err != nil {
		t.Fatalf("failed to allocate IP 2: %v", err)
	}

	if err := mgr.Save(allocator); err != nil {
		t.Fatalf("failed to save checkpoint: %v", err)
	}

	checkpoint, err := mgr.Load()
	if err != nil {
		t.Fatalf("failed to load checkpoint: %v", err)
	}

	if checkpoint.PodCIDR != "10.0.0.0/24" {
		t.Errorf("expected PodCIDR 10.0.0.0/24, got %s", checkpoint.PodCIDR)
	}

	if len(checkpoint.Records) != 2 {
		t.Errorf("expected 2 records, got %d", len(checkpoint.Records))
	}

	found1, found2 := false, false
	for _, r := range checkpoint.Records {
		if r.PodName == pod1Name && r.PodNamespace == pod1NS && r.IP == ip1.String() {
			found1 = true
		}
		if r.PodName == pod2Name && r.PodNamespace == pod2NS && r.IP == ip2.String() {
			found2 = true
		}
	}

	if !found1 {
		t.Errorf("record for pod1 not found or mismatch")
	}
	if !found2 {
		t.Errorf("record for pod2 not found or mismatch")
	}
}

func TestCheckpointRestore(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "checkpoint-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	checkpointPath := filepath.Join(tmpDir, "checkpoint.json")
	mgr := NewCheckpointManager(checkpointPath)

	allocator1, _ := NewNodeAllocator("10.0.0.0/24")
	allocator1.Allocate("pod1", "ns1")
	allocator1.Allocate("pod2", "ns2")

	if err := mgr.Save(allocator1); err != nil {
		t.Fatalf("failed to save: %v", err)
	}

	checkpoint, _ := mgr.Load()

	allocator2, _ := NewNodeAllocator("10.0.0.0/24")
	if err := mgr.Restore(allocator2, checkpoint); err != nil {
		t.Fatalf("failed to restore: %v", err)
	}

	ips1 := allocator1.GetAllocatedIPs()
	ips2 := allocator2.GetAllocatedIPs()

	if len(ips1) != len(ips2) {
		t.Errorf("allocation count mismatch: %d != %d", len(ips1), len(ips2))
	}

	for k, v1 := range ips1 {
		v2, exists := ips2[k]
		if !exists {
			t.Errorf("missing allocation for %s in restored allocator", k)
			continue
		}
		if v1.String() != v2.String() {
			t.Errorf("IP mismatch for %s: %s != %s", k, v1, v2)
		}
	}
}

func TestCheckpointAtomicWrite(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "checkpoint-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	checkpointPath := filepath.Join(tmpDir, "checkpoint.json")
	mgr := NewCheckpointManager(checkpointPath)
	allocator, _ := NewNodeAllocator("10.0.0.0/24")

	// We can't easily verify the rename happened, but we can check the temp file is gone
	if err := mgr.Save(allocator); err != nil {
		t.Fatalf("failed to save: %v", err)
	}

	tmpPath := checkpointPath + ".tmp"
	if _, err := os.Stat(tmpPath); !os.IsNotExist(err) {
		t.Errorf("temp file should not exist after Save")
	}

	if _, err := os.Stat(checkpointPath); os.IsNotExist(err) {
		t.Errorf("final checkpoint file should exist after Save")
	}
}

func TestCheckpointNotExists(t *testing.T) {
	mgr := NewCheckpointManager("/non/existent/path/checkpoint.json")
	if mgr.Exists() {
		t.Errorf("Exists() should return false for non-existent file")
	}
}

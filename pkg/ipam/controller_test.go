package ipam

import (
	"net"
	"testing"
)

func TestNewIPAMController(t *testing.T) {
	tests := []struct {
		cidr      string
		blockSize int
		wantErr   bool
	}{
		{"10.244.0.0/16", 24, false},
		{"192.168.0.0/20", 24, false},
		{"invalid-cidr", 24, true},
	}

	for _, tt := range tests {
		_, err := NewIPAMController(tt.cidr, tt.blockSize)
		if (err != nil) != tt.wantErr {
			t.Errorf("NewIPAMController(%s, %d) error = %v, wantErr %v", tt.cidr, tt.blockSize, err, tt.wantErr)
		}
	}
}

func TestAssignBlock(t *testing.T) {
	clusterCIDR := "10.244.0.0/16"
	blockSize := 24
	controller, _ := NewIPAMController(clusterCIDR, blockSize)

	block, err := controller.AssignBlock("node1")
	if err != nil {
		t.Fatalf("failed to assign block: %v", err)
	}

	_, clusterNet, _ := net.ParseCIDR(clusterCIDR)
	if !clusterNet.Contains(block.IP) {
		t.Errorf("assigned block %v is not within cluster CIDR %s", block, clusterCIDR)
	}

	ones, _ := block.Mask.Size()
	if ones != blockSize {
		t.Errorf("assigned block mask size = %d, want %d", ones, blockSize)
	}
}

func TestAssignMultipleBlocks(t *testing.T) {
	clusterCIDR := "10.244.0.0/16"
	controller, _ := NewIPAMController(clusterCIDR, 24)

	block1, _ := controller.AssignBlock("node1")
	block2, _ := controller.AssignBlock("node2")

	if block1.String() == block2.String() {
		t.Errorf("nodes assigned same block: %s", block1)
	}

	// Verify they don't overlap (for /24 they should be distinct)
	if block1.Contains(block2.IP) || block2.Contains(block1.IP) {
		t.Errorf("blocks overlap: %s and %s", block1, block2)
	}
}

func TestAssignSecondaryBlock(t *testing.T) {
	controller, _ := NewIPAMController("10.244.0.0/16", 24)
	nodeName := "node1"

	primary, _ := controller.AssignBlock(nodeName)
	secondary, err := controller.AssignSecondaryBlock(nodeName)
	if err != nil {
		t.Fatalf("failed to assign secondary block: %v", err)
	}

	if primary.String() == secondary.String() {
		t.Errorf("secondary block is same as primary: %s", secondary)
	}

	assignments, _ := controller.GetAssignment(nodeName)
	if len(assignments) != 2 {
		t.Errorf("node1 has %d assignments, want 2", len(assignments))
	}
}

func TestReleaseBlocks(t *testing.T) {
	controller, _ := NewIPAMController("10.244.0.0/16", 24)
	nodeName := "node1"

	controller.AssignBlock(nodeName)
	err := controller.ReleaseBlocks(nodeName)
	if err != nil {
		t.Fatalf("failed to release blocks: %v", err)
	}

	_, err = controller.GetAssignment(nodeName)
	if err == nil {
		t.Error("GetAssignment should have failed for released node")
	}
}

func TestIsBlockAvailable(t *testing.T) {
	// /30 cluster with /31 blocks -> only 2 blocks available
	controller, _ := NewIPAMController("10.0.0.0/30", 31)

	if !controller.IsBlockAvailable() {
		t.Error("expected blocks to be available initially")
	}

	controller.AssignBlock("n1")
	if !controller.IsBlockAvailable() {
		t.Error("expected 1 block still available")
	}

	controller.AssignBlock("n2")
	if controller.IsBlockAvailable() {
		t.Error("expected no blocks available after 2 assignments")
	}
}

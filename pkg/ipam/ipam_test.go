package ipam

import (
	"fmt"
	"net"
	"testing"
)

func TestNewNodeAllocator(t *testing.T) {
	tests := []struct {
		cidr    string
		wantErr bool
	}{
		{"10.244.0.0/24", false},
		{"192.168.1.0/28", false},
		{"invalid-cidr", true},
		{"10.0.0.1/33", true},
	}

	for _, tt := range tests {
		_, err := NewNodeAllocator(tt.cidr)
		if (err != nil) != tt.wantErr {
			t.Errorf("NewNodeAllocator(%s) error = %v, wantErr %v", tt.cidr, err, tt.wantErr)
		}
	}
}

func TestAllocate(t *testing.T) {
	cidr := "10.0.0.0/24"
	alloc, err := NewNodeAllocator(cidr)
	if err != nil {
		t.Fatalf("failed to create allocator: %v", err)
	}

	ip, err := alloc.Allocate("pod1", "default")
	if err != nil {
		t.Fatalf("failed to allocate IP: %v", err)
	}

	_, ipnet, _ := net.ParseCIDR(cidr)
	if !ipnet.Contains(ip) {
		t.Errorf("allocated IP %v is not within CIDR %s", ip, cidr)
	}

	// Network and broadcast addresses should be skipped
	if ip.Equal(ipnet.IP) {
		t.Errorf("allocated network address %v", ip)
	}
}

func TestAllocateMultiple(t *testing.T) {
	alloc, _ := NewNodeAllocator("10.0.0.0/24")
	ips := make(map[string]net.IP)

	pods := []struct {
		name string
		ns   string
	}{
		{"pod1", "default"},
		{"pod2", "default"},
		{"pod3", "kube-system"},
	}

	for _, p := range pods {
		ip, err := alloc.Allocate(p.name, p.ns)
		if err != nil {
			t.Fatalf("failed to allocate for %s: %v", p.name, err)
		}
		if oldIP, exists := ips[ip.String()]; exists {
			t.Errorf("duplicate IP %s allocated (previously for %s)", ip, oldIP)
		}
		ips[ip.String()] = net.IP(p.name) // just to track
	}
}

func TestRelease(t *testing.T) {
	alloc, _ := NewNodeAllocator("10.0.0.0/24")
	podName, podNS := "pod1", "default"

	ip, _ := alloc.Allocate(podName, podNS)
	if !alloc.IsAllocated(ip) {
		t.Errorf("IP %v should be allocated", ip)
	}

	err := alloc.Release(podName, podNS)
	if err != nil {
		t.Fatalf("failed to release IP: %v", err)
	}

	if alloc.IsAllocated(ip) {
		t.Errorf("IP %v should be released", ip)
	}

	// Re-allocate should succeed (likely getting the same IP)
	newIP, err := alloc.Allocate(podName, podNS)
	if err != nil {
		t.Fatalf("failed to re-allocate IP: %v", err)
	}
	if !newIP.Equal(ip) {
		t.Logf("got different IP on re-allocation: %v vs %v", newIP, ip)
	}
}

func TestIsAllocated(t *testing.T) {
	alloc, _ := NewNodeAllocator("10.0.0.0/24")
	ip, _ := alloc.Allocate("pod1", "default")

	if !alloc.IsAllocated(ip) {
		t.Errorf("IsAllocated(%v) = false, want true", ip)
	}

	otherIP := net.ParseIP("10.0.0.254")
	if alloc.IsAllocated(otherIP) {
		t.Errorf("IsAllocated(%v) = true, want false", otherIP)
	}
}

func TestUtilization(t *testing.T) {
	// /29 has size 8, usable 6
	alloc, _ := NewNodeAllocator("10.0.0.0/29")

	if util := alloc.Utilization(); util != 0 {
		t.Errorf("initial utilization = %v, want 0", util)
	}

	alloc.Allocate("p1", "d")
	if util := alloc.Utilization(); util != 1.0/6.0 {
		t.Errorf("utilization after 1 alloc = %v, want %v", util, 1.0/6.0)
	}

	for i := 2; i <= 6; i++ {
		alloc.Allocate(fmt.Sprintf("p%d", i), "d")
	}

	// Should be full
	if util := alloc.Utilization(); util != 1.0 {
		t.Errorf("utilization when full = %v, want 1.0", util)
	}
}

func TestAvailable(t *testing.T) {
	alloc, _ := NewNodeAllocator("10.0.0.0/29") // 6 usable IPs
	if avail := alloc.Available(); avail != 6 {
		t.Errorf("initial available = %d, want 6", avail)
	}

	alloc.Allocate("p1", "d")
	if avail := alloc.Available(); avail != 5 {
		t.Errorf("available after 1 alloc = %d, want 5", avail)
	}
}

func TestReconcile(t *testing.T) {
	alloc, _ := NewNodeAllocator("10.0.0.0/24")
	alloc.Allocate("pod1", "default")
	alloc.Allocate("pod2", "default")
	alloc.Allocate("pod3", "default")

	activePods := map[string]bool{
		"pod1/default": true,
		"pod2/default": true,
	}

	released := alloc.Reconcile(activePods)
	if len(released) != 1 {
		t.Errorf("Reconcile released %d IPs, want 1", len(released))
	}

	if alloc.IsAllocated(released[0]) {
		t.Errorf("released IP %v is still marked as allocated", released[0])
	}

	allocs := alloc.GetAllocatedIPs()
	if len(allocs) != 2 {
		t.Errorf("remaining allocations = %d, want 2", len(allocs))
	}
}

func TestAllocateExhaustion(t *testing.T) {
	// /30 has size 4, usable 2 (10.0.0.1, 10.0.0.2)
	alloc, _ := NewNodeAllocator("10.0.0.0/30")

	_, err := alloc.Allocate("p1", "d")
	if err != nil {
		t.Fatalf("first allocation failed: %v", err)
	}
	_, err = alloc.Allocate("p2", "d")
	if err != nil {
		t.Fatalf("second allocation failed: %v", err)
	}

	_, err = alloc.Allocate("p3", "d")
	if err == nil {
		t.Error("third allocation should have failed due to exhaustion")
	}
}

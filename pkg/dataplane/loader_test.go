package dataplane

import (
	"net"
	"os"
	"testing"
)

func TestEBPFInit(t *testing.T) {
	config := LoaderConfig{
		BPFMountPath: "/tmp/bpf",
		PinPath:      "/tmp/coordino",
	}
	dp := NewEBPFDataPlane(config)
	err := dp.Init(config)
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	if dp.config.BPFMountPath != "/tmp/bpf" {
		t.Errorf("Expected BPFMountPath /tmp/bpf, got %s", dp.config.BPFMountPath)
	}
}

func TestEBPFLoadPrograms(t *testing.T) {
	dp := NewEBPFDataPlane(LoaderConfig{PinPath: "/tmp/coordino"})
	err := dp.LoadPrograms()
	if err != nil {
		t.Fatalf("LoadPrograms failed: %v", err)
	}
	if !dp.IsHealthy() {
		t.Errorf("Expected DataPlane to be healthy")
	}
	if dp.programFDs["cni_tc_ingress"] == 0 {
		t.Errorf("Expected cni_tc_ingress program FD to be set")
	}
}

func TestEBPFAddRemoveEndpoint(t *testing.T) {
	dp := NewEBPFDataPlane(LoaderConfig{PinPath: "/tmp/coordino"})
	dp.LoadPrograms()

	podIP := net.ParseIP("10.0.0.1")
	identityID := uint32(1001)
	ifIndex := 5

	err := dp.AddPodEndpoint(podIP, identityID, ifIndex)
	if err != nil {
		t.Fatalf("AddPodEndpoint failed: %v", err)
	}

	endpoints := dp.GetEndpoints()
	if _, ok := endpoints[podIP.String()]; !ok {
		t.Errorf("Endpoint not found in endpoints map")
	}

	identityMap := dp.GetIdentityMap()
	ipUint := uint32(0x0a000001) // 10.0.0.1 in big endian? binary.BigEndian.Uint32(podIP.To4())
	// Let's check what AddPodEndpoint does
	// ipUint := binary.BigEndian.Uint32(ip)
	if identityMap[ipUint] != identityID {
		t.Errorf("Expected identity %d for IP %d, got %d", identityID, ipUint, identityMap[ipUint])
	}

	// Verify map manager entry
	val, err := dp.mapManager.LookupMapEntry("identity_map", podIP.To4())
	if err != nil {
		t.Fatalf("Identity map lookup failed: %v", err)
	}
	if len(val) != 4 {
		t.Errorf("Expected value size 4, got %d", len(val))
	}

	err = dp.RemovePodEndpoint(podIP)
	if err != nil {
		t.Fatalf("RemovePodEndpoint failed: %v", err)
	}

	endpoints = dp.GetEndpoints()
	if _, ok := endpoints[podIP.String()]; ok {
		t.Errorf("Endpoint still found in endpoints map after removal")
	}
}

func TestEBPFAttachDetachInterface(t *testing.T) {
	dp := NewEBPFDataPlane(LoaderConfig{PinPath: "/tmp/coordino"})
	err := dp.AttachToInterface("eth0")
	if err != nil {
		t.Fatalf("AttachToInterface failed: %v", err)
	}
	if !dp.attachedInterfaces["eth0"] {
		t.Errorf("Expected eth0 to be attached")
	}

	err = dp.DetachFromInterface("eth0")
	if err != nil {
		t.Fatalf("DetachFromInterface failed: %v", err)
	}
	if dp.attachedInterfaces["eth0"] {
		t.Errorf("Expected eth0 to be detached")
	}
}

func TestEBPFUpdateIdentity(t *testing.T) {
	dp := NewEBPFDataPlane(LoaderConfig{PinPath: "/tmp/coordino"})
	dp.LoadPrograms()

	podIP := net.ParseIP("10.0.0.2")
	dp.AddPodEndpoint(podIP, 1002, 6)

	err := dp.UpdateIdentity(podIP, 2002)
	if err != nil {
		t.Fatalf("UpdateIdentity failed: %v", err)
	}

	if dp.GetEndpoints()[podIP.String()].IdentityID != 2002 {
		t.Errorf("Expected updated identity 2002, got %d", dp.GetEndpoints()[podIP.String()].IdentityID)
	}
}

func TestIptablesInit(t *testing.T) {
	dp := NewIptablesDataPlane(LoaderConfig{})
	err := dp.Init(LoaderConfig{PinPath: "/tmp/iptables"})
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	err = dp.LoadPrograms()
	if err != nil {
		t.Fatalf("LoadPrograms failed: %v", err)
	}
	if !dp.IsHealthy() {
		t.Errorf("Expected IptablesDataPlane to be healthy")
	}
}

func TestIptablesAddRemoveEndpoint(t *testing.T) {
	dp := NewIptablesDataPlane(LoaderConfig{})
	dp.LoadPrograms()

	podIP := net.ParseIP("10.0.1.1")
	dp.AddPodEndpoint(podIP, 3001, 10)

	if _, ok := dp.endpoints[podIP.String()]; !ok {
		t.Errorf("Endpoint not found")
	}
	if len(dp.chains["COORDINO-FORWARD"]) == 0 {
		t.Errorf("Expected iptables rules to be added")
	}

	dp.RemovePodEndpoint(podIP)
	if _, ok := dp.endpoints[podIP.String()]; ok {
		t.Errorf("Endpoint still exists")
	}
}

func TestDetectKernelSupport(t *testing.T) {
	// This test depends on the environment. On macOS it should fail.
	supported, reason := DetectKernelSupport()
	if os.Getenv("GOOS") == "linux" {
		// Cannot guarantee success without real /proc and /sys
		t.Logf("Kernel support on Linux: %v, reason: %s", supported, reason)
	} else {
		if supported {
			t.Errorf("Expected DetectKernelSupport to fail on non-Linux, but it passed")
		}
	}
}

func TestDataPlaneInterface(t *testing.T) {
	var _ DataPlane = &EBPFDataPlane{}
	var _ DataPlane = &IptablesDataPlane{}
}

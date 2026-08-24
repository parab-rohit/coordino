package netns

import (
	"strings"
	"testing"
)

func TestVethNameGeneration(t *testing.T) {
	mgr := NewLinuxNetnsManager()
	containerID := "1234567890abcdef1234567890abcdef"
	name1 := mgr.generateHostVethName(containerID)
	name2 := mgr.generateHostVethName(containerID)

	if name1 != name2 {
		t.Errorf("Generated names are not deterministic: %s != %s", name1, name2)
	}

	if !strings.HasPrefix(name1, "veth") {
		t.Errorf("Generated name does not have prefix 'veth': %s", name1)
	}

	if len(name1) != 12 { // "veth" (4) + 8 chars of hash
		t.Errorf("Generated name length is incorrect: %d, expected 12", len(name1))
	}
}

func TestSetupPodNetwork(t *testing.T) {
	sim := NewSimulatedNetlinkOperator()
	mgr := NewLinuxNetnsManagerWithOperator(sim)

	config := NetnsConfig{
		ContainerID: "test-container",
		Netns:       "/proc/1234/ns/net",
		IfName:      "eth0",
		IP:          "10.0.0.5/24",
		Gateway:     "10.0.0.1",
		MTU:         1500,
	}

	veth, err := mgr.SetupPodNetwork(config)
	if err != nil {
		t.Fatalf("SetupPodNetwork failed: %v", err)
	}

	if veth.PodName != "eth0" {
		t.Errorf("Expected pod name eth0, got %s", veth.PodName)
	}

	hostName := mgr.generateHostVethName(config.ContainerID)
	if veth.HostName != hostName {
		t.Errorf("Expected host name %s, got %s", hostName, veth.HostName)
	}

	// Verify links in simulation
	if !sim.LinkExists(hostName) {
		t.Errorf("Host link %s not found in simulation", hostName)
	}
	if !sim.LinkExists("eth0") {
		t.Errorf("Pod link eth0 not found in simulation")
	}

	podLink := sim.Links["eth0"]
	if podLink.Netns != config.Netns {
		t.Errorf("Expected netns %s, got %s", config.Netns, podLink.Netns)
	}
	if podLink.Addr != config.IP {
		t.Errorf("Expected IP %s, got %s", config.IP, podLink.Addr)
	}
	if !podLink.Up {
		t.Errorf("Expected pod link to be up")
	}

	hostLink := sim.Links[hostName]
	if !hostLink.Up {
		t.Errorf("Expected host link to be up")
	}

	// Check operations log for route
	foundRoute := false
	for _, op := range sim.Operations {
		if strings.HasPrefix(op, "AddRoute:eth0:0.0.0.0/0:10.0.0.1") {
			foundRoute = true
			break
		}
	}
	if !foundRoute {
		t.Errorf("Route operation not found in log: %v", sim.Operations)
	}
}

func TestSetupWithMTU(t *testing.T) {
	sim := NewSimulatedNetlinkOperator()
	mgr := NewLinuxNetnsManagerWithOperator(sim)

	config := NetnsConfig{
		ContainerID: "test-mtu",
		Netns:       "/proc/1234/ns/net",
		IfName:      "eth0",
		MTU:         1450,
	}

	_, err := mgr.SetupPodNetwork(config)
	if err != nil {
		t.Fatalf("SetupPodNetwork failed: %v", err)
	}

	hostName := mgr.generateHostVethName(config.ContainerID)
	if sim.Links[hostName].MTU != 1450 {
		t.Errorf("Host MTU not set correctly: %d", sim.Links[hostName].MTU)
	}
	if sim.Links["eth0"].MTU != 1450 {
		t.Errorf("Pod MTU not set correctly: %d", sim.Links["eth0"].MTU)
	}
}

func TestTeardownPodNetwork(t *testing.T) {
	sim := NewSimulatedNetlinkOperator()
	mgr := NewLinuxNetnsManagerWithOperator(sim)

	config := NetnsConfig{
		ContainerID: "test-teardown",
		IfName:      "eth0",
	}

	// Setup first
	_, err := mgr.SetupPodNetwork(config)
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	hostName := mgr.generateHostVethName(config.ContainerID)
	if !sim.LinkExists(hostName) {
		t.Fatalf("Host link should exist before teardown")
	}

	// Teardown
	err = mgr.TeardownPodNetwork(config)
	if err != nil {
		t.Errorf("Teardown failed: %v", err)
	}

	if sim.LinkExists(hostName) {
		t.Errorf("Host link should be deleted after teardown")
	}
	if sim.LinkExists("eth0") {
		t.Errorf("Pod link should be deleted after teardown (peer deletion)")
	}
}

func TestCheckPodNetwork(t *testing.T) {
	sim := NewSimulatedNetlinkOperator()
	mgr := NewLinuxNetnsManagerWithOperator(sim)

	config := NetnsConfig{
		ContainerID: "test-check",
		IfName:      "eth0",
	}

	// 1. Check before setup (should fail)
	if err := mgr.CheckPodNetwork(config); err == nil {
		t.Errorf("CheckPodNetwork should fail before setup")
	}

	// 2. Setup
	_, err := mgr.SetupPodNetwork(config)
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	// 3. Check after setup (should pass)
	if err := mgr.CheckPodNetwork(config); err != nil {
		t.Errorf("CheckPodNetwork failed: %v", err)
	}

	// 4. Remove host link and check
	hostName := mgr.generateHostVethName(config.ContainerID)
	sim.DeleteLink(hostName)
	if err := mgr.CheckPodNetwork(config); err == nil {
		t.Errorf("CheckPodNetwork should fail if host link is missing")
	}
}

func TestSetupFailure(t *testing.T) {
	sim := NewSimulatedNetlinkOperator()
	mgr := NewLinuxNetnsManagerWithOperator(sim)

	config := NetnsConfig{
		ContainerID: "test-failure",
		Netns:       "/proc/1234/ns/net",
		IfName:      "eth0",
	}

	// Fail on MoveToNetns
	sim.FailOn = "MoveToNetns:eth0"

	_, err := mgr.SetupPodNetwork(config)
	if err == nil {
		t.Errorf("SetupPodNetwork should have failed")
	}

	// Verify cleanup: host veth should be deleted
	hostName := mgr.generateHostVethName(config.ContainerID)
	if sim.LinkExists(hostName) {
		t.Errorf("Host link %s should have been cleaned up after failure", hostName)
	}
}

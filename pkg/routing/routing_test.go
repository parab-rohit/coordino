package routing

import (
	"testing"
)

func TestNewRoutingBackend(t *testing.T) {
	bgp, err := NewRoutingBackend(ModeBGP, nil)
	if err != nil {
		t.Fatalf("failed to create BGP backend: %v", err)
	}
	if bgp.Mode() != ModeBGP {
		t.Errorf("expected mode BGP, got %s", bgp.Mode())
	}

	vxlan, err := NewRoutingBackend(ModeVXLAN, nil)
	if err != nil {
		t.Fatalf("failed to create VXLAN backend: %v", err)
	}
	if vxlan.Mode() != ModeVXLAN {
		t.Errorf("expected mode VXLAN, got %s", vxlan.Mode())
	}

	_, err = NewRoutingBackend("invalid", nil)
	if err == nil {
		t.Error("expected error for invalid mode, got nil")
	}
}

func TestBGPAddRemoveNode(t *testing.T) {
	backend := NewBGPBackend(BGPConfig{})
	localNode := NodeInfo{Name: "local", NodeIP: "10.0.0.1", PodCIDR: "10.1.0.0/24"}
	backend.Init(localNode)

	node1 := NodeInfo{Name: "node1", NodeIP: "10.0.0.2", PodCIDR: "10.1.1.0/24"}
	err := backend.AddNode(node1)
	if err != nil {
		t.Fatalf("AddNode failed: %v", err)
	}

	routes, _ := backend.GetRoutes()
	if len(routes) != 1 {
		t.Errorf("expected 1 route, got %d", len(routes))
	}
	if routes[0].DestCIDR != node1.PodCIDR {
		t.Errorf("expected route for %s, got %s", node1.PodCIDR, routes[0].DestCIDR)
	}

	err = backend.RemoveNode(node1.Name)
	if err != nil {
		t.Fatalf("RemoveNode failed: %v", err)
	}

	routes, _ = backend.GetRoutes()
	if len(routes) != 0 {
		t.Errorf("expected 0 routes after removal, got %d", len(routes))
	}
}

func TestBGPSyncRoutes(t *testing.T) {
	backend := NewBGPBackend(BGPConfig{})
	localNode := NodeInfo{Name: "local", NodeIP: "10.0.0.1", PodCIDR: "10.1.0.0/24"}
	backend.Init(localNode)

	nodes := []NodeInfo{
		{Name: "node1", NodeIP: "10.0.0.2", PodCIDR: "10.1.1.0/24"},
		{Name: "node2", NodeIP: "10.0.0.3", PodCIDR: "10.1.2.0/24"},
	}

	err := backend.SyncRoutes(nodes)
	if err != nil {
		t.Fatalf("SyncRoutes failed: %v", err)
	}

	routes, _ := backend.GetRoutes()
	if len(routes) != 2 {
		t.Errorf("expected 2 routes, got %d", len(routes))
	}

	// Sync with one node removed and one added
	nodes = []NodeInfo{
		{Name: "node2", NodeIP: "10.0.0.3", PodCIDR: "10.1.2.0/24"},
		{Name: "node3", NodeIP: "10.0.0.4", PodCIDR: "10.1.3.0/24"},
	}
	backend.SyncRoutes(nodes)

	routes, _ = backend.GetRoutes()
	if len(routes) != 2 {
		t.Errorf("expected 2 routes after sync, got %d", len(routes))
	}
}

func TestBGPPeerStatus(t *testing.T) {
	backend := NewBGPBackend(BGPConfig{})
	backend.Init(NodeInfo{Name: "local"})

	node1 := NodeInfo{Name: "node1", NodeIP: "10.0.0.2"}
	backend.AddNode(node1)

	status := backend.GetPeerStatus()
	peer, ok := status["node1"]
	if !ok {
		t.Fatal("node1 peer status not found")
	}
	if peer.State != "Established" {
		t.Errorf("expected state Established, got %s", peer.State)
	}
}

func TestVXLANAddRemoveNode(t *testing.T) {
	backend := NewVXLANBackend(VXLANConfig{InterfaceName: "vxlan0"})
	localNode := NodeInfo{Name: "local", NodeIP: "10.0.0.1"}
	backend.Init(localNode)

	node1 := NodeInfo{Name: "node1", NodeIP: "10.0.0.2", PodCIDR: "10.1.1.0/24"}
	backend.AddNode(node1)

	routes, _ := backend.GetRoutes()
	if len(routes) != 1 {
		t.Errorf("expected 1 route, got %d", len(routes))
	}
	if routes[0].Interface != "vxlan0" {
		t.Errorf("expected interface vxlan0, got %s", routes[0].Interface)
	}

	fdb := backend.GetFDB()
	if _, ok := fdb["node1"]; !ok {
		t.Error("FDB entry for node1 missing")
	}

	backend.RemoveNode("node1")
	routes, _ = backend.GetRoutes()
	if len(routes) != 0 {
		t.Error("expected 0 routes after removal")
	}
}

func TestVXLANSyncRoutes(t *testing.T) {
	backend := NewVXLANBackend(VXLANConfig{})
	backend.Init(NodeInfo{Name: "local"})

	nodes := []NodeInfo{
		{Name: "node1", NodeIP: "10.0.0.2", PodCIDR: "10.1.1.0/24"},
	}
	backend.SyncRoutes(nodes)

	routes, _ := backend.GetRoutes()
	if len(routes) != 1 {
		t.Errorf("expected 1 route, got %d", len(routes))
	}
}

func TestVXLANFDBEntries(t *testing.T) {
	backend := NewVXLANBackend(VXLANConfig{})
	backend.Init(NodeInfo{Name: "local"})

	node1 := NodeInfo{Name: "node1", NodeIP: "10.0.0.2"}
	backend.AddNode(node1)

	fdb := backend.GetFDB()
	entry, ok := fdb["node1"]
	if !ok {
		t.Fatal("FDB entry missing")
	}
	if entry.RemoteIP != node1.NodeIP {
		t.Errorf("expected remote IP %s, got %s", node1.NodeIP, entry.RemoteIP)
	}
}

func TestBackendModes(t *testing.T) {
	bgp := NewBGPBackend(BGPConfig{})
	if bgp.Mode() != ModeBGP {
		t.Errorf("expected ModeBGP, got %s", bgp.Mode())
	}

	vxlan := NewVXLANBackend(VXLANConfig{})
	if vxlan.Mode() != ModeVXLAN {
		t.Errorf("expected ModeVXLAN, got %s", vxlan.Mode())
	}
}

func TestBackendHealth(t *testing.T) {
	bgp := NewBGPBackend(BGPConfig{})
	if bgp.IsHealthy() {
		t.Error("expected BGP to be unhealthy before Init")
	}
	bgp.Init(NodeInfo{Name: "local"})

	// BGP needs at least one established peer to be healthy
	if bgp.IsHealthy() {
		t.Error("expected BGP to be unhealthy after Init but before adding a node")
	}

	bgp.AddNode(NodeInfo{Name: "node1", NodeIP: "10.0.0.2", PodCIDR: "10.1.1.0/24"})
	if !bgp.IsHealthy() {
		t.Error("expected BGP to be healthy after adding a peer")
	}

	vxlan := NewVXLANBackend(VXLANConfig{})
	if vxlan.IsHealthy() {
		t.Error("expected VXLAN to be unhealthy before Init")
	}
	vxlan.Init(NodeInfo{Name: "local"})
	if !vxlan.IsHealthy() {
		t.Error("expected VXLAN to be healthy after Init")
	}
}

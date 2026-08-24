package policy

import (
	"reflect"
	"testing"
)

func TestNewIdentityAllocator(t *testing.T) {
	a := NewIdentityAllocator()
	if a == nil {
		t.Fatal("NewIdentityAllocator returned nil")
	}
	if len(a.identities) != 0 {
		t.Errorf("Expected 0 identities, got %d", len(a.identities))
	}
	if len(a.hashToID) != 0 {
		t.Errorf("Expected 0 hashes, got %d", len(a.hashToID))
	}
}

func TestAllocateIdentity(t *testing.T) {
	a := NewIdentityAllocator()
	labels := map[string]string{"app": "web", "env": "prod"}
	id, err := a.AllocateIdentity(labels)
	if err != nil {
		t.Fatalf("AllocateIdentity failed: %v", err)
	}
	if id.ID == 0 {
		t.Error("Expected non-zero ID")
	}
	if !reflect.DeepEqual(id.Labels, labels) {
		t.Errorf("Expected labels %v, got %v", labels, id.Labels)
	}
	if id.RefCount != 1 {
		t.Errorf("Expected RefCount 1, got %d", id.RefCount)
	}
}

func TestAllocateIdentitySameLabels(t *testing.T) {
	a := NewIdentityAllocator()
	labels := map[string]string{"app": "web"}
	id1, err := a.AllocateIdentity(labels)
	if err != nil {
		t.Fatalf("First AllocateIdentity failed: %v", err)
	}
	id2, err := a.AllocateIdentity(labels)
	if err != nil {
		t.Fatalf("Second AllocateIdentity failed: %v", err)
	}
	if id1.ID != id2.ID {
		t.Errorf("Expected same ID, got %d and %d", id1.ID, id2.ID)
	}
	if id1.RefCount != 2 {
		t.Errorf("Expected RefCount 2, got %d", id1.RefCount)
	}
}

func TestAllocateIdentityDifferentLabels(t *testing.T) {
	a := NewIdentityAllocator()
	id1, _ := a.AllocateIdentity(map[string]string{"app": "web"})
	id2, _ := a.AllocateIdentity(map[string]string{"app": "db"})
	if id1.ID == id2.ID {
		t.Errorf("Expected different IDs, got %d for both", id1.ID)
	}
}

func TestReleaseIdentity(t *testing.T) {
	a := NewIdentityAllocator()
	labels := map[string]string{"app": "web"}
	id, _ := a.AllocateIdentity(labels)
	a.AllocateIdentity(labels) // RefCount = 2

	err := a.ReleaseIdentity(id.ID)
	if err != nil {
		t.Fatalf("ReleaseIdentity failed: %v", err)
	}
	if id.RefCount != 1 {
		t.Errorf("Expected RefCount 1, got %d", id.RefCount)
	}
}

func TestReleaseIdentityGarbageCollect(t *testing.T) {
	a := NewIdentityAllocator()
	labels := map[string]string{"app": "web"}
	id, _ := a.AllocateIdentity(labels)

	err := a.ReleaseIdentity(id.ID)
	if err != nil {
		t.Fatalf("ReleaseIdentity failed: %v", err)
	}

	_, exists := a.GetIdentity(id.ID)
	if exists {
		t.Error("Identity should have been removed")
	}
	if len(a.hashToID) != 0 {
		t.Error("hashToID should be empty")
	}
}

func TestGetIdentity(t *testing.T) {
	a := NewIdentityAllocator()
	labels := map[string]string{"app": "web"}
	id, _ := a.AllocateIdentity(labels)

	found, exists := a.GetIdentity(id.ID)
	if !exists {
		t.Fatal("Identity not found")
	}
	if found.ID != id.ID {
		t.Errorf("Expected ID %d, got %d", id.ID, found.ID)
	}

	_, exists = a.GetIdentity(999)
	if exists {
		t.Error("Identity 999 should not exist")
	}
}

func TestGetIdentityByLabels(t *testing.T) {
	a := NewIdentityAllocator()
	labels := map[string]string{"app": "web"}
	id, _ := a.AllocateIdentity(labels)

	found, exists := a.GetIdentityByLabels(labels)
	if !exists {
		t.Fatal("Identity not found by labels")
	}
	if found.ID != id.ID {
		t.Errorf("Expected ID %d, got %d", id.ID, found.ID)
	}

	_, exists = a.GetIdentityByLabels(map[string]string{"app": "none"})
	if exists {
		t.Error("Identity should not exist for these labels")
	}
}

func TestNodeReferences(t *testing.T) {
	a := NewIdentityAllocator()
	id, _ := a.AllocateIdentity(map[string]string{"app": "web"})

	err := a.AddNodeReference(id.ID, "node1")
	if err != nil {
		t.Fatalf("AddNodeReference failed: %v", err)
	}
	if !id.Nodes["node1"] {
		t.Error("node1 not found in identity nodes")
	}

	err = a.RemoveNodeReference(id.ID, "node1")
	if err != nil {
		t.Fatalf("RemoveNodeReference failed: %v", err)
	}
	if id.Nodes["node1"] {
		t.Error("node1 still found in identity nodes after removal")
	}
}

func TestGetIdentitiesForNode(t *testing.T) {
	a := NewIdentityAllocator()
	id1, _ := a.AllocateIdentity(map[string]string{"app": "web"})
	id2, _ := a.AllocateIdentity(map[string]string{"app": "db"})

	a.AddNodeReference(id1.ID, "node1")
	a.AddNodeReference(id2.ID, "node2")

	node1Ids := a.GetIdentitiesForNode("node1")
	if len(node1Ids) != 1 || node1Ids[0].ID != id1.ID {
		t.Errorf("Expected only id1 for node1, got %v", node1Ids)
	}

	node2Ids := a.GetIdentitiesForNode("node2")
	if len(node2Ids) != 1 || node2Ids[0].ID != id2.ID {
		t.Errorf("Expected only id2 for node2, got %v", node2Ids)
	}
}

func TestHashDeterminism(t *testing.T) {
	a := NewIdentityAllocator()
	labels1 := map[string]string{"app": "web", "env": "prod"}
	labels2 := map[string]string{"env": "prod", "app": "web"}

	hash1 := a.hashLabels(labels1)
	hash2 := a.hashLabels(labels2)

	if hash1 != hash2 {
		t.Errorf("Hashes should be identical regardless of order: %s vs %s", hash1, hash2)
	}
}

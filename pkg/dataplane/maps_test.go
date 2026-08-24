package dataplane

import (
	"bytes"
	"testing"
)

func TestEnsureMap(t *testing.T) {
	mm := NewMapManager("/tmp/bpf")
	pm := &PinnedMap{
		Name:       "test_map",
		Type:       MapTypeIdentity,
		MaxEntries: 100,
	}
	err := mm.EnsureMap(pm)
	if err != nil {
		t.Fatalf("EnsureMap failed: %v", err)
	}
	if _, ok := mm.maps["test_map"]; !ok {
		t.Errorf("Map not tracked")
	}
	if _, ok := mm.storage["test_map"]; !ok {
		t.Errorf("Map storage not initialized")
	}
}

func TestDeleteMap(t *testing.T) {
	mm := NewMapManager("/tmp/bpf")
	pm := &PinnedMap{Name: "test_map"}
	mm.EnsureMap(pm)
	err := mm.DeleteMap("test_map")
	if err != nil {
		t.Fatalf("DeleteMap failed: %v", err)
	}
	if _, ok := mm.maps["test_map"]; ok {
		t.Errorf("Map still tracked after deletion")
	}
}

func TestUpdateLookupEntry(t *testing.T) {
	mm := NewMapManager("/tmp/bpf")
	mm.EnsureMap(&PinnedMap{Name: "test_map"})

	key := []byte{1, 2, 3, 4}
	val := []byte{10, 20, 30, 40}

	err := mm.UpdateMapEntry("test_map", key, val)
	if err != nil {
		t.Fatalf("UpdateMapEntry failed: %v", err)
	}

	got, err := mm.LookupMapEntry("test_map", key)
	if err != nil {
		t.Fatalf("LookupMapEntry failed: %v", err)
	}
	if !bytes.Equal(got, val) {
		t.Errorf("Expected %v, got %v", val, got)
	}
}

func TestDeleteMapEntry(t *testing.T) {
	mm := NewMapManager("/tmp/bpf")
	mm.EnsureMap(&PinnedMap{Name: "test_map"})

	key := []byte{1, 2, 3, 4}
	mm.UpdateMapEntry("test_map", key, []byte{1})

	err := mm.DeleteMapEntry("test_map", key)
	if err != nil {
		t.Fatalf("DeleteMapEntry failed: %v", err)
	}

	_, err = mm.LookupMapEntry("test_map", key)
	if err == nil {
		t.Errorf("Expected error looking up deleted key")
	}
}

func TestGetMapStats(t *testing.T) {
	mm := NewMapManager("/tmp/bpf")
	mm.EnsureMap(&PinnedMap{Name: "test_map", MaxEntries: 100})
	mm.UpdateMapEntry("test_map", []byte{1}, []byte{1})

	stats := mm.GetMapStats()
	s, ok := stats["test_map"]
	if !ok {
		t.Fatalf("Stats for test_map not found")
	}
	if s.EntryCount != 1 {
		t.Errorf("Expected EntryCount 1, got %d", s.EntryCount)
	}
	if s.MaxEntries != 100 {
		t.Errorf("Expected MaxEntries 100, got %d", s.MaxEntries)
	}
	if s.Utilization != 0.01 {
		t.Errorf("Expected Utilization 0.01, got %f", s.Utilization)
	}
}

func TestRecoverMaps(t *testing.T) {
	mm := NewMapManager("/tmp/bpf")
	err := mm.RecoverMaps()
	if err != nil {
		t.Errorf("RecoverMaps failed: %v", err)
	}
}

func TestCleanupStaleMaps(t *testing.T) {
	mm := NewMapManager("/tmp/bpf")
	mm.storage["stale_map"] = make(map[string][]byte)

	err := mm.CleanupStaleMaps()
	if err != nil {
		t.Fatalf("CleanupStaleMaps failed: %v", err)
	}

	if _, ok := mm.storage["stale_map"]; ok {
		t.Errorf("Stale map not cleaned up")
	}
}

package policy

import (
	"sync"
	"testing"
	"time"
)

func TestPolicyStoreAddRemove(t *testing.T) {
	alloc := NewIdentityAllocator()
	compiler := NewCompiler(alloc)
	platform := NewPlatformRules()
	store := NewPolicyStore(compiler, platform)

	spec := NetworkPolicySpec{
		PodSelector: map[string]string{"app": "nginx"},
	}

	err := store.AddPolicy("test", "default", spec)
	if err != nil {
		t.Fatalf("AddPolicy failed: %v", err)
	}

	if _, ok := store.GetPolicy("test", "default"); !ok {
		t.Errorf("Policy not found in store")
	}

	err = store.RemovePolicy("test", "default")
	if err != nil {
		t.Fatalf("RemovePolicy failed: %v", err)
	}

	if _, ok := store.GetPolicy("test", "default"); ok {
		t.Errorf("Policy still found in store after removal")
	}
}

func TestPolicyStoreRecompile(t *testing.T) {
	alloc := NewIdentityAllocator()
	compiler := NewCompiler(alloc)
	platform := NewPlatformRules()
	store := NewPolicyStore(compiler, platform)

	spec := NetworkPolicySpec{
		PodSelector: map[string]string{"app": "nginx"},
		Ingress: []NetworkPolicyIngressRule{
			{From: nil, Ports: []NetworkPolicyPort{{Protocol: "TCP", Port: 80}}},
		},
	}

	store.AddPolicy("test", "default", spec)
	compiled := store.GetCompiledPolicy()

	if compiled == nil || len(compiled.Rules) == 0 {
		t.Errorf("Compiled policy is empty")
	}

	// Verify tenant rule is present
	found := false
	for _, r := range compiled.Rules {
		if r.Tier == TierTenant && r.Port == 80 {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Tenant rule not found in compiled results")
	}
}

func TestPolicyStoreNodeFiltering(t *testing.T) {
	alloc := NewIdentityAllocator()
	compiler := NewCompiler(alloc)
	store := NewPolicyStore(compiler, nil)

	// Target pod identity
	targetLabels := map[string]string{"app": "web"}
	targetIdentity, _ := alloc.AllocateIdentity(targetLabels)

	spec := NetworkPolicySpec{
		PodSelector: targetLabels,
		Ingress: []NetworkPolicyIngressRule{
			{From: nil, Ports: []NetworkPolicyPort{{Protocol: "TCP", Port: 80}}},
		},
	}
	store.AddPolicy("test", "default", spec)

	// Node has the target pod
	nodeIdentities := map[uint32]bool{targetIdentity.ID: true}
	nodePolicy := store.GetCompiledForNode(nodeIdentities)

	if len(nodePolicy.Rules) == 0 {
		t.Errorf("Expected rules for node, got none")
	}
}

func TestPolicyStoreVersion(t *testing.T) {
	alloc := NewIdentityAllocator()
	compiler := NewCompiler(alloc)
	store := NewPolicyStore(compiler, nil)

	v1 := store.GetVersion()
	store.AddPolicy("p1", "default", NetworkPolicySpec{})
	v2 := store.GetVersion()

	if v2 <= v1 {
		t.Errorf("Version did not increment: v1=%d, v2=%d", v1, v2)
	}
}

func TestPolicyStoreOnChange(t *testing.T) {
	alloc := NewIdentityAllocator()
	compiler := NewCompiler(alloc)
	store := NewPolicyStore(compiler, nil)

	var wg sync.WaitGroup
	wg.Add(1)
	store.SetOnChangeCallback(func() {
		wg.Done()
	})

	store.AddPolicy("p1", "default", NetworkPolicySpec{})

	// Wait for callback with timeout
	c := make(chan struct{})
	go func() {
		wg.Wait()
		c <- struct{}{}
	}()

	select {
	case <-c:
		// Success
	case <-time.After(1 * time.Second):
		t.Errorf("OnChange callback not triggered")
	}
}

package policy

import (
	"fmt"
	"sync"
	"time"
)

// PolicyStore manages NetworkPolicy objects and compiles them to IR.
type PolicyStore struct {
	policies map[string]*StoredPolicy // key: "namespace/name"
	compiler *Compiler
	compiled *CompiledPolicy // latest compiled result
	platform *PlatformRules
	version  int64
	mu       sync.RWMutex
	onChange func() // callback when policies change
}

// StoredPolicy represents a stored network policy.
type StoredPolicy struct {
	Name      string
	Namespace string
	Spec      NetworkPolicySpec
	AddedAt   time.Time
}

// NewPolicyStore creates a new PolicyStore.
func NewPolicyStore(compiler *Compiler, platform *PlatformRules) *PolicyStore {
	return &PolicyStore{
		policies: make(map[string]*StoredPolicy),
		compiler: compiler,
		platform: platform,
		version:  1,
	}
}

// AddPolicy add/updates a policy and triggers recompile.
func (s *PolicyStore) AddPolicy(name, namespace string, spec NetworkPolicySpec) error {
	s.mu.Lock()
	key := fmt.Sprintf("%s/%s", namespace, name)
	s.policies[key] = &StoredPolicy{
		Name:      name,
		Namespace: namespace,
		Spec:      spec,
		AddedAt:   time.Now(),
	}
	s.mu.Unlock()

	return s.Recompile()
}

// RemovePolicy removes a policy and triggers recompile.
func (s *PolicyStore) RemovePolicy(name, namespace string) error {
	s.mu.Lock()
	key := fmt.Sprintf("%s/%s", namespace, name)
	if _, ok := s.policies[key]; !ok {
		s.mu.Unlock()
		return fmt.Errorf("policy %s not found", key)
	}
	delete(s.policies, key)
	s.mu.Unlock()

	return s.Recompile()
}

// GetPolicy returns a policy by name and namespace.
func (s *PolicyStore) GetPolicy(name, namespace string) (*StoredPolicy, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	key := fmt.Sprintf("%s/%s", namespace, name)
	p, ok := s.policies[key]
	return p, ok
}

// ListPolicies returns all stored policies.
func (s *PolicyStore) ListPolicies() []*StoredPolicy {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var list []*StoredPolicy
	for _, p := range s.policies {
		list = append(list, p)
	}
	return list
}

// Recompile recompiles all policies into a single CompiledPolicy.
func (s *PolicyStore) Recompile() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var policiesToMerge []*CompiledPolicy

	// 1. Platform rules
	if s.platform != nil {
		platformRules := s.platform.GenerateRules()
		policiesToMerge = append(policiesToMerge, &CompiledPolicy{
			Rules:      platformRules,
			CompiledAt: time.Now(),
			Version:    time.Now().UnixNano(),
		})
	}

	// 2. Tenant policies
	for _, p := range s.policies {
		compiled, err := s.compiler.CompilePolicy(p.Name, p.Namespace, p.Spec)
		if err != nil {
			return err
		}
		policiesToMerge = append(policiesToMerge, compiled)
	}

	// 3. Merge everything
	s.compiled = s.compiler.MergeAndPrioritize(policiesToMerge...)
	s.version++

	if s.onChange != nil {
		// Run callback in a goroutine to avoid blocking
		go s.onChange()
	}

	return nil
}

// GetCompiledPolicy returns the latest compiled result.
func (s *PolicyStore) GetCompiledPolicy() *CompiledPolicy {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.compiled
}

// GetCompiledForNode returns filtered rules for a specific node.
func (s *PolicyStore) GetCompiledForNode(nodeIdentities map[uint32]bool) *CompiledPolicy {
	s.mu.RLock()
	compiled := s.compiled
	s.mu.RUnlock()

	if compiled == nil {
		return &CompiledPolicy{
			Rules:      []PolicyRule{},
			CompiledAt: time.Now(),
		}
	}

	filteredRules := s.compiler.FilterRulesForNode(compiled.Rules, nodeIdentities)
	return &CompiledPolicy{
		Rules:      filteredRules,
		CompiledAt: time.Now(),
		Version:    compiled.Version,
	}
}

// SetOnChangeCallback sets the change notification callback.
func (s *PolicyStore) SetOnChangeCallback(fn func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onChange = fn
}

// GetVersion returns the current version of the store.
func (s *PolicyStore) GetVersion() int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.version
}

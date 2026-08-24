package policy

import (
	"testing"
)

func TestCompilePolicyIngress(t *testing.T) {
	alloc := NewIdentityAllocator()
	compiler := NewCompiler(alloc)

	spec := NetworkPolicySpec{
		PodSelector: map[string]string{"app": "server"},
		Ingress: []NetworkPolicyIngressRule{
			{
				From: []NetworkPolicyPeer{
					{PodSelector: map[string]string{"app": "client"}},
				},
				Ports: []NetworkPolicyPort{
					{Protocol: "TCP", Port: 80},
				},
			},
		},
	}

	compiled, err := compiler.CompilePolicy("test-policy", "default", spec)
	if err != nil {
		t.Fatalf("Failed to compile policy: %v", err)
	}

	if len(compiled.Rules) != 1 {
		t.Errorf("Expected 1 rule, got %d", len(compiled.Rules))
	}

	rule := compiled.Rules[0]
	if rule.Port != 80 || rule.Proto != "TCP" || rule.Verdict != VerdictAllow {
		t.Errorf("Unexpected rule attributes: %+v", rule)
	}
}

func TestCompilePolicyEgress(t *testing.T) {
	alloc := NewIdentityAllocator()
	compiler := NewCompiler(alloc)

	spec := NetworkPolicySpec{
		PodSelector: map[string]string{"app": "client"},
		Egress: []NetworkPolicyEgressRule{
			{
				To: []NetworkPolicyPeer{
					{PodSelector: map[string]string{"app": "server"}},
				},
				Ports: []NetworkPolicyPort{
					{Protocol: "TCP", Port: 80},
				},
			},
		},
	}

	compiled, err := compiler.CompilePolicy("test-egress", "default", spec)
	if err != nil {
		t.Fatalf("Failed to compile policy: %v", err)
	}

	if len(compiled.Rules) != 1 {
		t.Errorf("Expected 1 rule, got %d", len(compiled.Rules))
	}

	rule := compiled.Rules[0]
	if rule.Port != 80 || rule.Proto != "TCP" || rule.Verdict != VerdictAllow {
		t.Errorf("Unexpected rule attributes: %+v", rule)
	}
}

func TestCompilePolicyWildcard(t *testing.T) {
	alloc := NewIdentityAllocator()
	compiler := NewCompiler(alloc)

	spec := NetworkPolicySpec{
		PodSelector: map[string]string{"app": "server"},
		Ingress: []NetworkPolicyIngressRule{
			{
				From:  nil, // Any
				Ports: nil, // Any
			},
		},
	}

	compiled, err := compiler.CompilePolicy("wildcard", "default", spec)
	if err != nil {
		t.Fatalf("Failed to compile policy: %v", err)
	}

	if len(compiled.Rules) != 1 {
		t.Errorf("Expected 1 rule, got %d", len(compiled.Rules))
	}

	rule := compiled.Rules[0]
	if rule.SrcIdentity != 0 || rule.Port != 0 {
		t.Errorf("Expected wildcard rule (Src=0, Port=0), got %+v", rule)
	}
}

func TestCompileNodeIsolationPolicy(t *testing.T) {
	alloc := NewIdentityAllocator()
	compiler := NewCompiler(alloc)

	spec := NodeIsolationPolicySpec{
		NodeSelector: map[string]string{"kubernetes.io/hostname": "node-1"},
		IngressRules: []IsolationRuleSpec{
			{
				CIDR:   "10.0.0.0/8",
				Ports:  []NetworkPolicyPort{{Protocol: "TCP", Port: 22}},
				Action: VerdictDeny,
			},
		},
	}

	compiled, err := compiler.CompileNodeIsolationPolicy("node-isolation", spec)
	if err != nil {
		t.Fatalf("Failed to compile node isolation policy: %v", err)
	}

	if len(compiled.Rules) != 1 {
		t.Errorf("Expected 1 rule, got %d", len(compiled.Rules))
	}

	rule := compiled.Rules[0]
	if rule.Tier != TierNodeIsolation || rule.Verdict != VerdictDeny || rule.Port != 22 {
		t.Errorf("Unexpected rule: %+v", rule)
	}
}

func TestMergeAndPrioritize(t *testing.T) {
	alloc := NewIdentityAllocator()
	compiler := NewCompiler(alloc)

	// Isolation policy (Tier 0) - Deny all to port 22
	p1, _ := compiler.CompileNodeIsolationPolicy("iso", NodeIsolationPolicySpec{
		IngressRules: []IsolationRuleSpec{{Action: VerdictDeny, Ports: []NetworkPolicyPort{{Protocol: "TCP", Port: 22}}}},
	})

	// Platform policy (Tier 1) - Allow DNS
	p2 := compiler.CompilePlatformRules()

	// Tenant policy (Tier 2) - Allow all to port 80
	p3, _ := compiler.CompilePolicy("tenant", "default", NetworkPolicySpec{
		PodSelector: map[string]string{"app": "web"},
		Ingress:     []NetworkPolicyIngressRule{{From: nil, Ports: []NetworkPolicyPort{{Protocol: "TCP", Port: 80}}}},
	})

	merged := compiler.MergeAndPrioritize(p1, p2, p3)

	if len(merged.Rules) < 3 {
		t.Errorf("Expected at least 3 rules, got %d", len(merged.Rules))
	}

	// First rule should be TierNodeIsolation
	if merged.Rules[0].Tier != TierNodeIsolation {
		t.Errorf("Priority error: First rule tier is %d, want 0", merged.Rules[0].Tier)
	}
}

func TestFilterRulesForNode(t *testing.T) {
	compiler := NewCompiler(NewIdentityAllocator())

	rules := []PolicyRule{
		{SrcIdentity: 1, DstIdentity: 2, Port: 80},
		{SrcIdentity: 3, DstIdentity: 4, Port: 80},
		{SrcIdentity: 0, DstIdentity: 5, Port: 53}, // Wildcard src
	}

	nodeIdentities := map[uint32]bool{2: true}
	filtered := compiler.FilterRulesForNode(rules, nodeIdentities)

	// Should keep rule 1 (dst=2) and rule 3 (src=0)
	if len(filtered) != 2 {
		t.Errorf("Expected 2 filtered rules, got %d", len(filtered))
	}
}

package policy

import (
	"sync"
	"time"
)

// Verdict defines the policy decision for a traffic flow.
type Verdict string

const (
	VerdictAllow Verdict = "allow"
	VerdictDeny  Verdict = "deny"
)

// Policy tiers for prioritization.
const (
	TierNodeIsolation    = 0
	TierPlatformMandated = 1
	TierTenant           = 2
)

// PolicyRule is the intermediate representation of a single network policy rule.
type PolicyRule struct {
	SrcIdentity     uint32
	DstIdentity     uint32
	Proto           string
	Port            int
	Verdict         Verdict
	PolicyName      string
	PolicyNamespace string
	Tier            int
}

// CompiledPolicy contains the set of IR rules derived from one or more network policies.
type CompiledPolicy struct {
	Rules      []PolicyRule
	CompiledAt time.Time
	Version    int64
}

// NetworkPolicySpec is a minimal representation of a K8s NetworkPolicy spec.
type NetworkPolicySpec struct {
	PodSelector map[string]string
	Ingress     []NetworkPolicyIngressRule
	Egress      []NetworkPolicyEgressRule
}

// NetworkPolicyIngressRule defines allowed ingress traffic.
type NetworkPolicyIngressRule struct {
	From  []NetworkPolicyPeer
	Ports []NetworkPolicyPort
}

// NetworkPolicyEgressRule defines allowed egress traffic.
type NetworkPolicyEgressRule struct {
	To    []NetworkPolicyPeer
	Ports []NetworkPolicyPort
}

// NetworkPolicyPeer defines a source or destination for traffic.
type NetworkPolicyPeer struct {
	PodSelector       map[string]string
	NamespaceSelector map[string]string
	IPBlock           *IPBlock
}

// IPBlock defines a CIDR range and exceptions.
type IPBlock struct {
	CIDR   string
	Except []string
}

// NetworkPolicyPort defines a protocol and port.
type NetworkPolicyPort struct {
	Protocol string
	Port     int
}

// NodeIsolationPolicySpec is a minimal representation of a node isolation policy.
type NodeIsolationPolicySpec struct {
	// Minimal contract for node isolation
	NodeSelector map[string]string
}

// Compiler converts NetworkPolicy CRDs into internal PolicyRule IR.
type Compiler struct {
	identityAllocator *IdentityAllocator
	mu                sync.RWMutex
}

// NewCompiler creates a new Compiler.
func NewCompiler(allocator *IdentityAllocator) *Compiler {
	return &Compiler{
		identityAllocator: allocator,
	}
}

// CompilePolicy converts a network policy spec into PolicyRules.
func (c *Compiler) CompilePolicy(name, namespace string, spec NetworkPolicySpec) (*CompiledPolicy, error) {
	// TODO: Implement complex selector resolution logic to map PodSelectors to Identities
	return &CompiledPolicy{
		Rules:      []PolicyRule{},
		CompiledAt: time.Now(),
		Version:    time.Now().UnixNano(),
	}, nil
}

// CompileNodeIsolationPolicy converts a node isolation policy spec into PolicyRules.
func (c *Compiler) CompileNodeIsolationPolicy(name string, spec NodeIsolationPolicySpec) (*CompiledPolicy, error) {
	// TODO: Implement node isolation policy compilation logic
	return &CompiledPolicy{
		Rules:      []PolicyRule{},
		CompiledAt: time.Now(),
		Version:    time.Now().UnixNano(),
	}, nil
}

// FilterRulesForNode returns only rules relevant to identities present on the node.
func (c *Compiler) FilterRulesForNode(rules []PolicyRule, nodeIdentities map[uint32]bool) []PolicyRule {
	var filtered []PolicyRule
	for _, rule := range rules {
		if nodeIdentities[rule.SrcIdentity] || nodeIdentities[rule.DstIdentity] {
			filtered = append(filtered, rule)
		}
	}
	return filtered
}

// MergeAndPrioritize merges multiple compiled policies respecting tier priority.
func (c *Compiler) MergeAndPrioritize(policies ...*CompiledPolicy) *CompiledPolicy {
	var allRules []PolicyRule
	for _, p := range policies {
		if p != nil {
			allRules = append(allRules, p.Rules...)
		}
	}

	// TODO: Implement actual prioritization logic based on Tier and other factors
	return &CompiledPolicy{
		Rules:      allRules,
		CompiledAt: time.Now(),
		Version:    time.Now().UnixNano(),
	}
}

package policy

import (
	"fmt"
	"sort"
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
	NodeSelector map[string]string
	IngressRules []IsolationRuleSpec
	EgressRules  []IsolationRuleSpec
	Priority     int
}

// IsolationRuleSpec defines a rule for node isolation.
type IsolationRuleSpec struct {
	CIDR   string
	Ports  []NetworkPolicyPort
	Action Verdict
}

// Compiler converts NetworkPolicy CRDs into internal PolicyRule IR.
type Compiler struct {
	identityAllocator *IdentityAllocator
	selectorCache     *SelectorCache
	mu                sync.RWMutex
}

// NewCompiler creates a new Compiler.
func NewCompiler(allocator *IdentityAllocator) *Compiler {
	return &Compiler{
		identityAllocator: allocator,
		selectorCache:     NewSelectorCache(),
	}
}

// CompilePolicy converts a network policy spec into PolicyRules.
func (c *Compiler) CompilePolicy(name, namespace string, spec NetworkPolicySpec) (*CompiledPolicy, error) {
	// 1. Resolve PodSelector to target identities
	dstIDs := c.resolveSelectorToIdentities(spec.PodSelector)

	var rules []PolicyRule

	// 2. Ingress rules
	for _, ingress := range spec.Ingress {
		srcIDs := c.resolvePeers(ingress.From)
		ports := ingress.Ports
		if len(ports) == 0 {
			ports = []NetworkPolicyPort{{Protocol: "ANY", Port: 0}}
		}

		for _, dstID := range dstIDs {
			for _, srcID := range srcIDs {
				for _, port := range ports {
					rules = append(rules, PolicyRule{
						SrcIdentity:     srcID,
						DstIdentity:     dstID,
						Proto:           port.Protocol,
						Port:            port.Port,
						Verdict:         VerdictAllow,
						PolicyName:      name,
						PolicyNamespace: namespace,
						Tier:            TierTenant,
					})
				}
			}
		}
	}

	// 3. Egress rules
	for _, egress := range spec.Egress {
		egressDstIDs := c.resolvePeers(egress.To)
		ports := egress.Ports
		if len(ports) == 0 {
			ports = []NetworkPolicyPort{{Protocol: "ANY", Port: 0}}
		}

		for _, srcID := range dstIDs {
			for _, dstID := range egressDstIDs {
				for _, port := range ports {
					rules = append(rules, PolicyRule{
						SrcIdentity:     srcID,
						DstIdentity:     dstID,
						Proto:           port.Protocol,
						Port:            port.Port,
						Verdict:         VerdictAllow,
						PolicyName:      name,
						PolicyNamespace: namespace,
						Tier:            TierTenant,
					})
				}
			}
		}
	}

	return &CompiledPolicy{
		Rules:      rules,
		CompiledAt: time.Now(),
		Version:    time.Now().UnixNano(),
	}, nil
}

func (c *Compiler) resolveSelectorToIdentities(selector map[string]string) []uint32 {
	var ids []uint32
	seen := make(map[uint32]bool)

	podKeys := c.selectorCache.EvaluateSelector(selector)

	c.selectorCache.mu.RLock()
	for podKey := range podKeys {
		labels := c.selectorCache.podLabels[podKey]
		if id, ok := c.identityAllocator.GetIdentityByLabels(labels); ok {
			if !seen[id.ID] {
				ids = append(ids, id.ID)
				seen[id.ID] = true
			}
		}
	}
	c.selectorCache.mu.RUnlock()

	// If no pods currently match, allocate an identity for the exact selector labels
	// as requested: "allocate identity for selected labels"
	if len(ids) == 0 {
		if id, err := c.identityAllocator.AllocateIdentity(selector); err == nil {
			ids = append(ids, id.ID)
		}
	}

	return ids
}

func (c *Compiler) resolvePeers(peers []NetworkPolicyPeer) []uint32 {
	if len(peers) == 0 {
		return []uint32{0} // identity 0 = wildcard
	}

	var identities []uint32
	seen := make(map[uint32]bool)

	for _, peer := range peers {
		if peer.IPBlock != nil {
			continue
		}

		peerIDs := c.resolveSelectorToIdentities(peer.PodSelector)
		for _, id := range peerIDs {
			if !seen[id] {
				identities = append(identities, id)
				seen[id] = true
			}
		}
	}

	return identities
}

// CompileNodeIsolationPolicy converts a node isolation policy spec into PolicyRules.
func (c *Compiler) CompileNodeIsolationPolicy(name string, spec NodeIsolationPolicySpec) (*CompiledPolicy, error) {
	var rules []PolicyRule

	// Ingress rules
	for _, ir := range spec.IngressRules {
		ports := ir.Ports
		if len(ports) == 0 {
			ports = []NetworkPolicyPort{{Protocol: "ANY", Port: 0}}
		}
		for _, port := range ports {
			rules = append(rules, PolicyRule{
				SrcIdentity: 0,
				DstIdentity: 0,
				Proto:       port.Protocol,
				Port:        port.Port,
				Verdict:     ir.Action,
				PolicyName:  name,
				Tier:        TierNodeIsolation,
			})
		}
	}

	// Egress
	for _, er := range spec.EgressRules {
		ports := er.Ports
		if len(ports) == 0 {
			ports = []NetworkPolicyPort{{Protocol: "ANY", Port: 0}}
		}
		for _, port := range ports {
			rules = append(rules, PolicyRule{
				SrcIdentity: 0,
				DstIdentity: 0,
				Proto:       port.Protocol,
				Port:        port.Port,
				Verdict:     er.Action,
				PolicyName:  name,
				Tier:        TierNodeIsolation,
			})
		}
	}

	return &CompiledPolicy{
		Rules:      rules,
		CompiledAt: time.Now(),
		Version:    time.Now().UnixNano(),
	}, nil
}

// CompilePlatformRules returns platform-mandated allow rules (DNS, monitoring).
func (c *Compiler) CompilePlatformRules() *CompiledPolicy {
	p := NewPlatformRules()
	rules := p.GenerateRules()
	return &CompiledPolicy{
		Rules:      rules,
		CompiledAt: time.Now(),
		Version:    time.Now().UnixNano(),
	}
}

// FilterRulesForNode returns only rules relevant to identities present on the node.
func (c *Compiler) FilterRulesForNode(rules []PolicyRule, nodeIdentities map[uint32]bool) []PolicyRule {
	var filtered []PolicyRule
	for _, rule := range rules {
		if rule.SrcIdentity == 0 || rule.DstIdentity == 0 || nodeIdentities[rule.SrcIdentity] || nodeIdentities[rule.DstIdentity] {
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

	// Sort rules
	sort.SliceStable(allRules, func(i, j int) bool {
		if allRules[i].Tier != allRules[j].Tier {
			return allRules[i].Tier < allRules[j].Tier
		}
		scoreI := specificityScore(allRules[i])
		scoreJ := specificityScore(allRules[j])
		if scoreI != scoreJ {
			return scoreI > scoreJ
		}
		return allRules[i].PolicyName < allRules[j].PolicyName
	})

	// Deduplicate and resolve conflicts (same src/dst/proto/port)
	var finalRules []PolicyRule
	seen := make(map[string]bool)
	for _, r := range allRules {
		key := fmt.Sprintf("%d-%d-%s-%d", r.SrcIdentity, r.DstIdentity, r.Proto, r.Port)
		if !seen[key] {
			finalRules = append(finalRules, r)
			seen[key] = true
		}
	}

	return &CompiledPolicy{
		Rules:      finalRules,
		CompiledAt: time.Now(),
		Version:    time.Now().UnixNano(),
	}
}

func specificityScore(r PolicyRule) int {
	score := 0
	if r.SrcIdentity != 0 {
		score++
	}
	if r.DstIdentity != 0 {
		score++
	}
	if r.Port != 0 {
		score++
	}
	return score
}

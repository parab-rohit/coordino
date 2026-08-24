package nodeisolation

import (
	"errors"
	"sync"
)

// Direction defines the traffic direction for isolation rules.
type Direction string

const (
	DirectionIngress Direction = "Ingress"
	DirectionEgress  Direction = "Egress"
)

// PortRule defines the protocol and port for a rule.
type PortRule struct {
	Protocol string
	Port     int
}

// IsolationRule defines a specific isolation rule.
type IsolationRule struct {
	Direction   Direction
	CIDR        string
	Ports       []PortRule
	Action      string // Allow or Deny
	Description string
}

// PolicyEnforcer defines the interface for applying rules to the data plane.
type PolicyEnforcer interface {
	EnforceIsolationRule(rule IsolationRule) error
	RemoveIsolationRule(rule IsolationRule) error
}

// HostPolicy manages node-to-node and pod-to-host isolation rules.
type HostPolicy struct {
	rules         []IsolationRule
	defaultAction string
	mu            sync.RWMutex
}

// NewHostPolicy creates a new HostPolicy with a default action.
func NewHostPolicy(defaultAction string) *HostPolicy {
	if defaultAction == "" {
		defaultAction = "Deny"
	}
	return &HostPolicy{
		defaultAction: defaultAction,
		rules:         []IsolationRule{},
	}
}

// DefaultPodToHostRules returns standard allowlist for pod-to-host communication.
func DefaultPodToHostRules() []IsolationRule {
	return []IsolationRule{
		{
			Direction:   DirectionIngress,
			Ports:       []PortRule{{Protocol: "TCP", Port: 10250}},
			Action:      "Allow",
			Description: "Allow kubelet health checks",
		},
		{
			Direction:   DirectionIngress,
			Ports:       []PortRule{{Protocol: "TCP", Port: 9100}},
			Action:      "Allow",
			Description: "Allow node-exporter scrape",
		},
		{
			Direction:   DirectionEgress,
			Ports:       []PortRule{{Protocol: "UDP", Port: 53}, {Protocol: "TCP", Port: 53}},
			Action:      "Allow",
			Description: "Allow DNS",
		},
		{
			Direction:   DirectionIngress,
			Action:      "Deny",
			Description: "Deny all other pod-to-host traffic",
		},
		{
			Direction:   DirectionEgress,
			Action:      "Deny",
			Description: "Deny all other pod-to-host traffic",
		},
	}
}

// DefaultNodeToNodeRules returns standard rules for node-to-node communication.
func DefaultNodeToNodeRules(apiServerCIDR string, apiServerPort int) []IsolationRule {
	return []IsolationRule{
		{
			Direction:   DirectionEgress,
			CIDR:        apiServerCIDR,
			Ports:       []PortRule{{Protocol: "TCP", Port: apiServerPort}},
			Action:      "Allow",
			Description: "Allow egress to K8s API server",
		},
		{
			Direction:   DirectionEgress,
			Ports:       []PortRule{{Protocol: "UDP", Port: 51820}},
			Action:      "Allow",
			Description: "Allow egress to WireGuard peers",
		},
		{
			Direction:   DirectionEgress,
			Action:      "Deny",
			Description: "Deny all other node-to-node egress",
		},
	}
}

// AddRule adds a new isolation rule.
func (hp *HostPolicy) AddRule(rule IsolationRule) {
	hp.mu.Lock()
	defer hp.mu.Unlock()
	hp.rules = append(hp.rules, rule)
}

// RemoveRule removes an isolation rule by its index.
func (hp *HostPolicy) RemoveRule(index int) error {
	hp.mu.Lock()
	defer hp.mu.Unlock()

	if index < 0 || index >= len(hp.rules) {
		return errors.New("index out of bounds")
	}

	hp.rules = append(hp.rules[:index], hp.rules[index+1:]...)
	return nil
}

// GetRules returns a copy of the current isolation rules.
func (hp *HostPolicy) GetRules() []IsolationRule {
	hp.mu.RLock()
	defer hp.mu.RUnlock()

	rules := make([]IsolationRule, len(hp.rules))
	copy(rules, hp.rules)
	return rules
}

// Validate checks for consistency in the rules.
func (hp *HostPolicy) Validate() error {
	hp.mu.RLock()
	defer hp.mu.RUnlock()

	for _, rule := range hp.rules {
		if rule.Direction != DirectionIngress && rule.Direction != DirectionEgress {
			return errors.New("invalid direction in rule: " + string(rule.Direction))
		}
		if rule.Action != "Allow" && rule.Action != "Deny" {
			return errors.New("invalid action in rule: " + rule.Action)
		}
	}
	return nil
}

// ApplyToDataPlane applies the current rules using the provided enforcer.
func (hp *HostPolicy) ApplyToDataPlane(enforcer PolicyEnforcer) error {
	hp.mu.RLock()
	defer hp.mu.RUnlock()

	for _, rule := range hp.rules {
		if err := enforcer.EnforceIsolationRule(rule); err != nil {
			return err
		}
	}
	// TODO: Handle default action in data plane.
	return nil
}

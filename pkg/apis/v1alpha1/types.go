package v1alpha1

import (
	"time"
)

// TypeMeta describes an individual object in an API response or request
// with strings representing the type of the object and its API schema version.
type TypeMeta struct {
	Kind       string `json:"kind,omitempty"`
	APIVersion string `json:"apiVersion,omitempty"`
}

// ObjectMeta is metadata that all persisted resources must have, which includes all objects users must create.
type ObjectMeta struct {
	Name              string            `json:"name,omitempty"`
	Namespace         string            `json:"namespace,omitempty"`
	Labels            map[string]string `json:"labels,omitempty"`
	Annotations       map[string]string `json:"annotations,omitempty"`
	CreationTimestamp time.Time         `json:"creationTimestamp,omitempty"`
	ResourceVersion   string            `json:"resourceVersion,omitempty"`
	UID               string            `json:"uid,omitempty"`
}

// ListMeta describes metadata that synthetic resources must have, including lists and various status objects.
type ListMeta struct {
	ResourceVersion string `json:"resourceVersion,omitempty"`
	Continue        string `json:"continue,omitempty"`
}

// Condition contains details for the current condition of this resource.
type Condition struct {
	Type               string    `json:"type"`
	Status             string    `json:"status"`
	LastTransitionTime time.Time `json:"lastTransitionTime"`
	Reason             string    `json:"reason"`
	Message            string    `json:"message"`
}

// --- IPPool ---

// IPPool defines a pool of IP addresses for allocation.
type IPPool struct {
	TypeMeta   `json:",inline"`
	ObjectMeta `json:"metadata,omitempty"`

	Spec   IPPoolSpec   `json:"spec,omitempty"`
	Status IPPoolStatus `json:"status,omitempty"`
}

// IPPoolSpec defines the desired state of IPPool.
type IPPoolSpec struct {
	CIDR        string                      `json:"cidr"`
	BlockSize   int                         `json:"blockSize"`
	Allocations map[string]IPPoolAllocation `json:"allocations,omitempty"`
}

// IPPoolAllocation represents an individual allocation within the pool.
type IPPoolAllocation struct {
	CIDR        string    `json:"cidr"`
	NodeName    string    `json:"nodeName"`
	AllocatedAt time.Time `json:"allocatedAt"`
}

// IPPoolStatus defines the observed state of IPPool.
type IPPoolStatus struct {
	TotalBlocks     int `json:"totalBlocks"`
	AllocatedBlocks int `json:"allocatedBlocks"`
	FreeBlocks      int `json:"freeBlocks"`
}

// IPPoolList is a list of IPPool resources.
type IPPoolList struct {
	TypeMeta `json:",inline"`
	ListMeta `json:"metadata,omitempty"`

	Items []IPPool `json:"items"`
}

// --- NodeConfig ---

// NodeConfigPhase describes the current phase of the NodeConfig.
type NodeConfigPhase string

const (
	// NodeConfigPending indicates the node configuration is pending.
	NodeConfigPending NodeConfigPhase = "Pending"
	// NodeConfigActive indicates the node configuration is active.
	NodeConfigActive NodeConfigPhase = "Active"
	// NodeConfigDraining indicates the node is being drained.
	NodeConfigDraining NodeConfigPhase = "Draining"
)

// NodeConfig defines the configuration for a specific node.
type NodeConfig struct {
	TypeMeta   `json:",inline"`
	ObjectMeta `json:"metadata,omitempty"`

	Spec   NodeConfigSpec   `json:"spec,omitempty"`
	Status NodeConfigStatus `json:"status,omitempty"`
}

// NodeConfigSpec defines the desired state of NodeConfig.
type NodeConfigSpec struct {
	NodeName           string   `json:"nodeName"`
	PodCIDR            string   `json:"podCIDR"`
	SecondaryPodCIDRs  []string `json:"secondaryPodCIDRs,omitempty"`
	WireGuardPublicKey string   `json:"wireGuardPublicKey"`
	AgentVersion       string   `json:"agentVersion"`
}

// NodeConfigStatus defines the observed state of NodeConfig.
type NodeConfigStatus struct {
	Phase         NodeConfigPhase `json:"phase"`
	LastHeartbeat time.Time       `json:"lastHeartbeat"`
	AllocatedIPs  int             `json:"allocatedIPs"`
	Conditions    []Condition     `json:"conditions,omitempty"`
}

// NodeConfigList is a list of NodeConfig resources.
type NodeConfigList struct {
	TypeMeta `json:",inline"`
	ListMeta `json:"metadata,omitempty"`

	Items []NodeConfig `json:"items"`
}

// --- Identity ---

// Identity defines a security identity based on labels.
type Identity struct {
	TypeMeta   `json:",inline"`
	ObjectMeta `json:"metadata,omitempty"`

	Spec   IdentitySpec   `json:"spec,omitempty"`
	Status IdentityStatus `json:"status,omitempty"`
}

// IdentitySpec defines the desired state of Identity.
type IdentitySpec struct {
	ID        uint32            `json:"id"`
	Labels    map[string]string `json:"labels"`
	LabelHash string            `json:"labelHash"`
}

// IdentityStatus defines the observed state of Identity.
type IdentityStatus struct {
	RefCount int      `json:"refCount"`
	Nodes    []string `json:"nodes,omitempty"`
}

// IdentityList is a list of Identity resources.
type IdentityList struct {
	TypeMeta `json:",inline"`
	ListMeta `json:"metadata,omitempty"`

	Items []Identity `json:"items"`
}

// --- PolicyIR ---

// PolicyIR defines the Intermediate Representation of a security policy for a node.
type PolicyIR struct {
	TypeMeta   `json:",inline"`
	ObjectMeta `json:"metadata,omitempty"`

	Spec   PolicyIRSpec   `json:"spec,omitempty"`
	Status PolicyIRStatus `json:"status,omitempty"`
}

// PolicyIRSpec defines the desired state of PolicyIR.
type PolicyIRSpec struct {
	NodeName string         `json:"nodeName"`
	Rules    []PolicyIRRule `json:"rules"`
}

// PolicyIRRule defines an individual policy rule.
type PolicyIRRule struct {
	SrcIdentity uint32 `json:"srcIdentity"`
	DstIdentity uint32 `json:"dstIdentity"`
	Proto       int    `json:"proto"`
	Port        int    `json:"port"`
	Verdict     string `json:"verdict"`
}

// PolicyIRStatus defines the observed state of PolicyIR.
type PolicyIRStatus struct {
	LastCompiled time.Time `json:"lastCompiled"`
	RuleCount    int       `json:"ruleCount"`
	Applied      bool      `json:"applied"`
}

// PolicyIRList is a list of PolicyIR resources.
type PolicyIRList struct {
	TypeMeta `json:",inline"`
	ListMeta `json:"metadata,omitempty"`

	Items []PolicyIR `json:"items"`
}

// --- NodeIsolationPolicy ---

// NodeIsolationPolicy defines isolation rules applied to nodes matching a selector.
type NodeIsolationPolicy struct {
	TypeMeta   `json:",inline"`
	ObjectMeta `json:"metadata,omitempty"`

	Spec   NodeIsolationPolicySpec   `json:"spec,omitempty"`
	Status NodeIsolationPolicyStatus `json:"status,omitempty"`
}

// NodeIsolationPolicySpec defines the desired state of NodeIsolationPolicy.
type NodeIsolationPolicySpec struct {
	NodeSelector map[string]string `json:"nodeSelector"`
	IngressRules []IsolationRule   `json:"ingressRules,omitempty"`
	EgressRules  []IsolationRule   `json:"egressRules,omitempty"`
	Priority     int               `json:"priority"`
}

// IsolationRule defines a rule for isolation.
type IsolationRule struct {
	CIDR   string          `json:"cidr"`
	Ports  []IsolationPort `json:"ports,omitempty"`
	Action string          `json:"action"`
}

// IsolationPort defines a protocol and port.
type IsolationPort struct {
	Protocol string `json:"protocol"`
	Port     int    `json:"port"`
}

// NodeIsolationPolicyStatus defines the observed state of NodeIsolationPolicy.
type NodeIsolationPolicyStatus struct {
	Applied       bool      `json:"applied"`
	LastApplied   time.Time `json:"lastApplied"`
	NodesAffected int       `json:"nodesAffected"`
}

// NodeIsolationPolicyList is a list of NodeIsolationPolicy resources.
type NodeIsolationPolicyList struct {
	TypeMeta `json:",inline"`
	ListMeta `json:"metadata,omitempty"`

	Items []NodeIsolationPolicy `json:"items"`
}

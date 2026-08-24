package netns

import (
	"crypto/sha256"
	"fmt"
)

// VethPair represents a virtual ethernet pair connecting pod and host namespaces.
type VethPair struct {
	HostName string // veth name on host side (e.g., "veth1a2b3c")
	PodName  string // veth name inside pod (usually "eth0")
	HostMAC  string
	PodMAC   string
}

// NetnsConfig holds the configuration for setting up a pod's network namespace.
type NetnsConfig struct {
	ContainerID string
	Netns       string // path to network namespace (e.g., /proc/1234/ns/net)
	IfName      string // interface name inside container (usually "eth0")
	IP          string // IP address with prefix (e.g., "10.0.0.5/24")
	Gateway     string // default gateway IP
	MTU         int    // MTU for the veth pair
}

// NetnsManager defines the interface for network namespace operations.
type NetnsManager interface {
	SetupPodNetwork(config NetnsConfig) (*VethPair, error)
	TeardownPodNetwork(config NetnsConfig) error
	CheckPodNetwork(config NetnsConfig) error
}

// LinuxNetnsManager implements NetnsManager using netlink syscalls.
type LinuxNetnsManager struct {
	hostIfPrefix string          // prefix for host-side veth names (default: "veth")
	nl           NetlinkOperator // abstraction for netlink operations
}

// NewLinuxNetnsManager creates a new LinuxNetnsManager with default "veth" prefix.
func NewLinuxNetnsManager() *LinuxNetnsManager {
	return &LinuxNetnsManager{
		hostIfPrefix: "veth",
		nl:           &RealNetlinkOperator{},
	}
}

// NewLinuxNetnsManagerWithOperator creates a new LinuxNetnsManager with a custom NetlinkOperator for testing.
func NewLinuxNetnsManagerWithOperator(op NetlinkOperator) *LinuxNetnsManager {
	return &LinuxNetnsManager{
		hostIfPrefix: "veth",
		nl:           op,
	}
}

func (l *LinuxNetnsManager) generateHostVethName(containerID string) string {
	h := sha256.Sum256([]byte(containerID))
	return fmt.Sprintf("%s%x", l.hostIfPrefix, h[:4])
}

// SetupPodNetwork implements NetnsManager.SetupPodNetwork.
func (l *LinuxNetnsManager) SetupPodNetwork(config NetnsConfig) (*VethPair, error) {
	hostName := l.generateHostVethName(config.ContainerID)
	podName := config.IfName

	// 1. Create veth pair
	if err := l.nl.CreateVethPair(hostName, podName); err != nil {
		return nil, fmt.Errorf("failed to create veth pair: %v", err)
	}

	// Ensure cleanup on failure
	var success bool
	defer func() {
		if !success {
			l.nl.DeleteLink(hostName)
		}
	}()

	// 2. Move pod-side to netns
	if err := l.nl.MoveToNetns(podName, config.Netns); err != nil {
		return nil, fmt.Errorf("failed to move interface %s to netns %s: %v", podName, config.Netns, err)
	}

	// 3. Set IP on pod-side
	if err := l.nl.AddAddress(podName, config.IP); err != nil {
		return nil, fmt.Errorf("failed to add address to %s: %v", podName, err)
	}

	// 4. Set both interfaces UP
	if err := l.nl.SetInterfaceUp(hostName); err != nil {
		return nil, fmt.Errorf("failed to set host interface %s up: %v", hostName, err)
	}
	if err := l.nl.SetInterfaceUp(podName); err != nil {
		return nil, fmt.Errorf("failed to set pod interface %s up: %v", podName, err)
	}

	// 5. Add default route via gateway in pod netns
	if config.Gateway != "" {
		if err := l.nl.AddRoute(podName, "0.0.0.0/0", config.Gateway); err != nil {
			return nil, fmt.Errorf("failed to add default route: %v", err)
		}
	}

	// 6. Set MTU
	if config.MTU > 0 {
		if err := l.nl.SetMTU(hostName, config.MTU); err != nil {
			return nil, fmt.Errorf("failed to set MTU on host interface: %v", err)
		}
		if err := l.nl.SetMTU(podName, config.MTU); err != nil {
			return nil, fmt.Errorf("failed to set MTU on pod interface: %v", err)
		}
	}

	hostMAC, err := l.nl.GetMAC(hostName)
	if err != nil {
		return nil, fmt.Errorf("failed to get host MAC: %v", err)
	}
	podMAC, err := l.nl.GetMAC(podName)
	if err != nil {
		return nil, fmt.Errorf("failed to get pod MAC: %v", err)
	}

	success = true
	return &VethPair{
		HostName: hostName,
		PodName:  podName,
		HostMAC:  hostMAC,
		PodMAC:   podMAC,
	}, nil
}

// TeardownPodNetwork implements NetnsManager.TeardownPodNetwork.
func (l *LinuxNetnsManager) TeardownPodNetwork(config NetnsConfig) error {
	hostName := l.generateHostVethName(config.ContainerID)
	if err := l.nl.DeleteLink(hostName); err != nil {
		return fmt.Errorf("failed to delete host veth %s: %v", hostName, err)
	}
	return nil
}

// CheckPodNetwork implements NetnsManager.CheckPodNetwork.
func (l *LinuxNetnsManager) CheckPodNetwork(config NetnsConfig) error {
	hostName := l.generateHostVethName(config.ContainerID)
	if !l.nl.LinkExists(hostName) {
		return fmt.Errorf("host veth %s does not exist", hostName)
	}
	if !l.nl.LinkExists(config.IfName) {
		return fmt.Errorf("pod interface %s does not exist", config.IfName)
	}
	return nil
}

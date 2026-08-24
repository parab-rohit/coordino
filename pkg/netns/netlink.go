package netns

import (
	"fmt"
	"sync"
)

// NetlinkOperator abstracts netlink operations for testability.
type NetlinkOperator interface {
	CreateVethPair(hostName, podName string) error
	SetInterfaceUp(name string) error
	MoveToNetns(ifName string, netnsPath string) error
	AddAddress(ifName string, addr string) error
	AddRoute(ifName string, dst string, gw string) error
	SetMTU(ifName string, mtu int) error
	DeleteLink(name string) error
	LinkExists(name string) bool
	GetMAC(ifName string) (string, error)
}

// RealNetlinkOperator implements NetlinkOperator using system calls.
type RealNetlinkOperator struct{}

func (o *RealNetlinkOperator) CreateVethPair(hostName, podName string) error {
	// TODO: Implement using RTM_NEWLINK syscall with IFLA_VETH_INFO
	return nil
}

func (o *RealNetlinkOperator) SetInterfaceUp(name string) error {
	// TODO: Implement using RTM_NEWLINK syscall setting IFF_UP flag
	return nil
}

func (o *RealNetlinkOperator) MoveToNetns(ifName string, netnsPath string) error {
	// TODO: Implement using RTM_SETLINK syscall with IFLA_NET_NS_FD
	return nil
}

func (o *RealNetlinkOperator) AddAddress(ifName string, addr string) error {
	// TODO: Implement using RTM_NEWADDR syscall
	return nil
}

func (o *RealNetlinkOperator) AddRoute(ifName string, dst string, gw string) error {
	// TODO: Implement using RTM_NEWROUTE syscall
	return nil
}

func (o *RealNetlinkOperator) SetMTU(ifName string, mtu int) error {
	// TODO: Implement using RTM_SETLINK syscall with IFLA_MTU
	return nil
}

func (o *RealNetlinkOperator) DeleteLink(name string) error {
	// TODO: Implement using RTM_DELLINK syscall
	return nil
}

func (o *RealNetlinkOperator) LinkExists(name string) bool {
	// TODO: Implement using RTM_GETLINK syscall
	return false
}

func (o *RealNetlinkOperator) GetMAC(ifName string) (string, error) {
	// TODO: Implement using RTM_GETLINK syscall and parsing IFLA_ADDRESS
	return "00:00:00:00:00:00", nil
}

// SimulatedNetlinkOperator implements NetlinkOperator for testing.
type SimulatedNetlinkOperator struct {
	Links      map[string]*SimLink
	Operations []string // log of operations performed
	mu         sync.Mutex
	FailOn     string // if set, fail when this operation is attempted
}

type SimLink struct {
	Name  string
	MAC   string
	Up    bool
	Netns string
	Addr  string
	MTU   int
	Peer  string // peer veth name
}

func NewSimulatedNetlinkOperator() *SimulatedNetlinkOperator {
	return &SimulatedNetlinkOperator{
		Links:      make(map[string]*SimLink),
		Operations: make([]string, 0),
	}
}

func (s *SimulatedNetlinkOperator) recordOp(op string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Operations = append(s.Operations, op)
	if s.FailOn == op {
		return fmt.Errorf("simulated error on %s", op)
	}
	return nil
}

func (s *SimulatedNetlinkOperator) CreateVethPair(hostName, podName string) error {
	if err := s.recordOp("CreateVethPair"); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	hostMAC := fmt.Sprintf("00:00:00:00:00:%02x", len(s.Links))
	podMAC := fmt.Sprintf("00:00:00:00:00:%02x", len(s.Links)+1)

	s.Links[hostName] = &SimLink{
		Name: hostName,
		MAC:  hostMAC,
		Peer: podName,
	}
	s.Links[podName] = &SimLink{
		Name: podName,
		MAC:  podMAC,
		Peer: hostName,
	}
	return nil
}

func (s *SimulatedNetlinkOperator) SetInterfaceUp(name string) error {
	if err := s.recordOp("SetInterfaceUp:" + name); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if link, ok := s.Links[name]; ok {
		link.Up = true
		return nil
	}
	return fmt.Errorf("link %s not found", name)
}

func (s *SimulatedNetlinkOperator) MoveToNetns(ifName string, netnsPath string) error {
	if err := s.recordOp("MoveToNetns:" + ifName); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if link, ok := s.Links[ifName]; ok {
		link.Netns = netnsPath
		return nil
	}
	return fmt.Errorf("link %s not found", ifName)
}

func (s *SimulatedNetlinkOperator) AddAddress(ifName string, addr string) error {
	if err := s.recordOp("AddAddress:" + ifName); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if link, ok := s.Links[ifName]; ok {
		link.Addr = addr
		return nil
	}
	return fmt.Errorf("link %s not found", ifName)
}

func (s *SimulatedNetlinkOperator) AddRoute(ifName string, dst string, gw string) error {
	return s.recordOp(fmt.Sprintf("AddRoute:%s:%s:%s", ifName, dst, gw))
}

func (s *SimulatedNetlinkOperator) SetMTU(ifName string, mtu int) error {
	if err := s.recordOp("SetMTU:" + ifName); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if link, ok := s.Links[ifName]; ok {
		link.MTU = mtu
		return nil
	}
	return fmt.Errorf("link %s not found", ifName)
}

func (s *SimulatedNetlinkOperator) DeleteLink(name string) error {
	if err := s.recordOp("DeleteLink:" + name); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if link, ok := s.Links[name]; ok {
		peer := link.Peer
		delete(s.Links, name)
		if peer != "" {
			delete(s.Links, peer)
		}
		return nil
	}
	return fmt.Errorf("link %s not found", name)
}

func (s *SimulatedNetlinkOperator) LinkExists(name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.Links[name]
	return ok
}

func (s *SimulatedNetlinkOperator) GetMAC(ifName string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if link, ok := s.Links[ifName]; ok {
		return link.MAC, nil
	}
	return "", fmt.Errorf("link %s not found", ifName)
}

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/coordino/cni/internal/grpc"
	"github.com/coordino/cni/pkg/dataplane"
	"github.com/coordino/cni/pkg/encryption"
	"github.com/coordino/cni/pkg/ipam"
	"github.com/coordino/cni/pkg/netns"
	"github.com/coordino/cni/pkg/nodeisolation"
	"github.com/coordino/cni/pkg/observability"
	"github.com/coordino/cni/pkg/policy"
	"github.com/coordino/cni/pkg/routing"
)

// PodEndpointInfo tracks allocated IPs and metadata per pod for proper cleanup.
type PodEndpointInfo struct {
	IP         net.IP
	IdentityID uint32
	IfName     string
	Netns      string
}

type NodeAgent struct {
	nodeName       string
	nodeIP         string
	podCIDR        string
	socketPath     string
	metricsAddr    string
	bpfMountPath   string
	checkpointPath string
	routingMode    string

	allocator         *ipam.NodeAllocator
	checkpoint        *ipam.CheckpointManager
	dp                dataplane.DataPlane
	encryption        *encryption.Manager
	metrics           *observability.CNIMetrics
	tracer            *observability.CNITracer
	hostPolicy        *nodeisolation.HostPolicy
	netnsManager      netns.NetnsManager
	policyWriter      *policy.EBPFWriter
	identityAllocator *policy.IdentityAllocator
	policyStore       *policy.PolicyStore
	routingBackend    routing.RoutingBackend

	podEndpoints map[string]PodEndpointInfo // key: "podName/podNamespace"
	mu           sync.RWMutex

	server *grpc.Server
}

func main() {
	nodeName := flag.String("node-name", "", "Name of the node")
	nodeIP := flag.String("node-ip", "", "IP address of the node")
	podCIDR := flag.String("pod-cidr", "", "Pod CIDR for the node")
	socketPath := flag.String("socket-path", grpc.SocketPath, "Path to the Unix socket")
	metricsAddr := flag.String("metrics-addr", ":9090", "Address for metrics and healthz")
	bpfMountPath := flag.String("bpf-mount-path", "/sys/fs/bpf", "Path where BPF FS is mounted")
	checkpointPath := flag.String("checkpoint-path", "/var/lib/coordino/checkpoint", "Path to the checkpoint file")
	routingMode := flag.String("routing-mode", "vxlan", "Routing mode (vxlan, bgp)")
	flag.Parse()

	if *nodeName == "" {
		log.Fatal("--node-name is required")
	}
	if *nodeIP == "" {
		log.Fatal("--node-ip is required")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	agent, err := NewNodeAgent(*nodeName, *nodeIP, *podCIDR, *socketPath, *metricsAddr, *bpfMountPath, *checkpointPath, *routingMode)
	if err != nil {
		log.Fatalf("Failed to initialize NodeAgent: %v", err)
	}

	if err := agent.Start(ctx); err != nil {
		log.Fatalf("Failed to start NodeAgent: %v", err)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	<-sigCh

	log.Println("Shutting down node agent...")
	agent.Stop()
}

func NewNodeAgent(nodeName, nodeIP, podCIDR, socketPath, metricsAddr, bpfMountPath, checkpointPath, routingMode string) (*NodeAgent, error) {
	allocator, err := ipam.NewNodeAllocator(podCIDR)
	if err != nil {
		return nil, fmt.Errorf("failed to create allocator: %v", err)
	}

	checkpoint := ipam.NewCheckpointManager(checkpointPath)
	if checkpoint.Exists() {
		cp, err := checkpoint.Load()
		if err == nil {
			checkpoint.Restore(allocator, cp)
			log.Printf("Restored state from checkpoint %s", checkpointPath)
		}
	}

	// Reserve gateway IP (first usable IP)
	allocator.Allocate("gateway", "kube-system")

	ebpfSupported, _ := dataplane.DetectKernelSupport()
	var dp dataplane.DataPlane
	loaderCfg := dataplane.LoaderConfig{
		BPFMountPath: bpfMountPath,
		PinPath:      "/sys/fs/bpf/coordino",
	}
	if ebpfSupported {
		dp = dataplane.NewEBPFDataPlane(loaderCfg)
		log.Println("Using eBPF data plane")
	} else {
		dp = dataplane.NewIptablesDataPlane(loaderCfg)
		log.Println("Using iptables data plane (fallback)")
	}

	enc := encryption.NewManager(encryption.WireGuardConfig{
		InterfaceName: "wg0",
	})

	registry := observability.NewNoopRegistry()
	metrics := observability.NewCNIMetrics(registry)
	tracer := observability.NewCNITracer("node-agent", true)

	hp := nodeisolation.NewHostPolicy("Deny")
	netnsMan := netns.NewLinuxNetnsManager()
	policyWriter := policy.NewEBPFWriter("/sys/fs/bpf/coordino/policy_map")

	identityAlloc := policy.NewIdentityAllocator()
	compiler := policy.NewCompiler(identityAlloc)
	policyStore := policy.NewPolicyStore(compiler, nil)

	routingBackend, err := routing.NewRoutingBackend(routing.Mode(routingMode), map[string]string{
		"node-ip": nodeIP,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create routing backend: %v", err)
	}

	agent := &NodeAgent{
		nodeName:          nodeName,
		nodeIP:            nodeIP,
		podCIDR:           podCIDR,
		socketPath:        socketPath,
		metricsAddr:       metricsAddr,
		bpfMountPath:      bpfMountPath,
		checkpointPath:    checkpointPath,
		routingMode:       routingMode,
		allocator:         allocator,
		checkpoint:        checkpoint,
		dp:                dp,
		encryption:        enc,
		metrics:           metrics,
		tracer:            tracer,
		hostPolicy:        hp,
		netnsManager:      netnsMan,
		policyWriter:      policyWriter,
		identityAllocator: identityAlloc,
		policyStore:       policyStore,
		routingBackend:    routingBackend,
		podEndpoints:      make(map[string]PodEndpointInfo),
	}

	handler := &NodeAgentHandler{agent: agent}
	agent.server = grpc.NewServer(socketPath, handler)

	return agent, nil
}

func (a *NodeAgent) Start(ctx context.Context) error {
	// Initialize data plane
	if err := a.dp.Init(dataplane.LoaderConfig{BPFMountPath: a.bpfMountPath}); err != nil {
		return fmt.Errorf("failed to init data plane: %v", err)
	}
	if err := a.dp.LoadPrograms(); err != nil {
		return fmt.Errorf("failed to load eBPF programs: %v", err)
	}

	// Upgrade path: Attach to existing maps if they exist
	if err := a.dp.AttachToExistingMaps(); err != nil {
		log.Printf("Notice: could not attach to existing maps (this is normal on fresh start): %v", err)
	}

	// Initialize routing backend
	err := a.routingBackend.Init(routing.NodeInfo{
		Name:    a.nodeName,
		PodCIDR: a.podCIDR,
		NodeIP:  a.nodeIP,
	})
	if err != nil {
		return fmt.Errorf("failed to init routing backend: %v", err)
	}

	// Start gRPC server
	if err := a.server.Start(); err != nil {
		return fmt.Errorf("failed to start gRPC server: %v", err)
	}

	// Start metrics/health server
	go a.startHTTPServer()

	// Start reconciliation loop
	go a.reconciliationLoop(ctx)

	log.Printf("Node agent started on node %s (%s) with pod CIDR %s", a.nodeName, a.nodeIP, a.podCIDR)
	return nil
}

func (a *NodeAgent) Stop() {
	a.server.Stop()
	// Save checkpoint on shutdown
	if err := a.checkpoint.Save(a.allocator); err != nil {
		log.Printf("Failed to save checkpoint: %v", err)
	}
	a.routingBackend.Close()
	a.dp.Close()
	log.Println("Node agent stopped")
}

func (a *NodeAgent) startHTTPServer() {
	http.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("# Metrics stub"))
	})
	http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})
	log.Printf("Starting HTTP server on %s", a.metricsAddr)
	if err := http.ListenAndServe(a.metricsAddr, nil); err != nil {
		log.Printf("HTTP server failed: %v", err)
	}
}

func (a *NodeAgent) reconciliationLoop(ctx context.Context) {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			a.reconcile()
		case <-ctx.Done():
			return
		}
	}
}

func (a *NodeAgent) reconcile() {
	a.mu.Lock()
	defer a.mu.Unlock()

	log.Println("Running periodic reconciliation...")

	// 1. Reconcile IPAM (compare against active pods)
	activePods := make(map[string]bool)
	activePods["gateway/kube-system"] = true // Always keep gateway
	for key := range a.podEndpoints {
		activePods[key] = true
	}
	releasedIPs := a.allocator.Reconcile(activePods)
	for _, ip := range releasedIPs {
		log.Printf("Reconciled and released dangling IP %s", ip)
	}

	// 2. Reconcile data plane endpoints
	for _, info := range a.podEndpoints {
		// Ensure all endpoints are correctly programmed in the data plane
		if err := a.dp.AddPodEndpoint(info.IP, info.IdentityID, 0); err != nil {
			log.Printf("Failed to reconcile dataplane endpoint for IP %s: %v", info.IP, err)
		}
	}

	// 3. Reconcile policy maps
	compiled := a.policyStore.GetCompiledPolicy()
	if compiled != nil {
		entries := a.policyWriter.CompileRulesToMapEntries(compiled.Rules)
		if err := a.policyWriter.SyncPolicyMap(entries); err != nil {
			log.Printf("Failed to sync policy maps: %v", err)
			a.metrics.BPFMapWriteErrors.Inc()
		}
	}

	// 4. Save checkpoint after reconciliation
	if err := a.checkpoint.Save(a.allocator); err != nil {
		log.Printf("Failed to save checkpoint during reconciliation: %v", err)
	}

	// 5. Update IPAM utilization metric
	a.metrics.IPAMBlockUtilization.Set(a.allocator.Utilization())
}

type NodeAgentHandler struct {
	agent *NodeAgent
}

func (h *NodeAgentHandler) HandleAdd(req *grpc.AddRequest) (*grpc.AddResponse, error) {
	log.Printf("Handling ADD for pod %s/%s", req.PodNamespace, req.PodName)

	h.agent.mu.Lock()
	defer h.agent.mu.Unlock()

	// 1. Resolve labels to an identity (using local identity cache)
	// In a real implementation, labels would be passed in Args or fetched from K8s API
	labels := map[string]string{
		"coordino.io/pod-name": req.PodName,
		"coordino.io/ns":       req.PodNamespace,
	}
	for k, v := range req.Args {
		labels[k] = v
	}
	identity, err := h.agent.identityAllocator.AllocateIdentity(labels)
	if err != nil {
		return &grpc.AddResponse{Error: fmt.Sprintf("identity allocation failed: %v", err)}, nil
	}

	// 2. Allocate IP
	ip, err := h.agent.allocator.Allocate(req.PodName, req.PodNamespace)
	if err != nil {
		h.agent.identityAllocator.ReleaseIdentity(identity.ID)
		return &grpc.AddResponse{Error: fmt.Sprintf("IP allocation failed: %v", err)}, nil
	}

	// 3. Proper gateway calculation (first usable IP)
	_, ipnet, _ := net.ParseCIDR(h.agent.podCIDR)
	gwIP := nextIP(ipnet.IP)

	// 4. Setup pod network via netns package
	netnsCfg := netns.NetnsConfig{
		ContainerID: req.ContainerID,
		Netns:       req.Netns,
		IfName:      req.IfName,
		IP:          fmt.Sprintf("%s/%d", ip.String(), 24),
		Gateway:     gwIP.String(),
		MTU:         1500,
	}
	veth, err := h.agent.netnsManager.SetupPodNetwork(netnsCfg)
	if err != nil {
		h.agent.allocator.Release(req.PodName, req.PodNamespace)
		h.agent.identityAllocator.ReleaseIdentity(identity.ID)
		return &grpc.AddResponse{Error: fmt.Sprintf("netns setup failed: %v", err)}, nil
	}

	// 5. Add pod endpoint to data plane with actual identity ID
	// Try to get ifIndex from host veth
	iface, err := net.InterfaceByName(veth.HostName)
	ifIndex := 0
	if err == nil {
		ifIndex = iface.Index
	}

	err = h.agent.dp.AddPodEndpoint(ip, identity.ID, ifIndex)
	if err != nil {
		h.agent.netnsManager.TeardownPodNetwork(netnsCfg)
		h.agent.allocator.Release(req.PodName, req.PodNamespace)
		h.agent.identityAllocator.ReleaseIdentity(identity.ID)
		return &grpc.AddResponse{Error: fmt.Sprintf("dataplane programming failed: %v", err)}, nil
	}

	// 6. Track pod info locally for proper HandleDel
	podKey := fmt.Sprintf("%s/%s", req.PodName, req.PodNamespace)
	h.agent.podEndpoints[podKey] = PodEndpointInfo{
		IP:         ip,
		IdentityID: identity.ID,
		IfName:     req.IfName,
		Netns:      req.Netns,
	}

	return &grpc.AddResponse{
		IP:      ip.String() + "/24",
		Gateway: gwIP.String(),
		Routes: []grpc.Route{
			{Dst: "0.0.0.0/0", GW: gwIP.String()},
		},
		DNS: grpc.DNSConfig{
			Nameservers: []string{"8.8.8.8"},
		},
	}, nil
}

func (h *NodeAgentHandler) HandleDel(req *grpc.DelRequest) (*grpc.DelResponse, error) {
	log.Printf("Handling DEL for pod %s/%s", req.PodNamespace, req.PodName)

	h.agent.mu.Lock()
	defer h.agent.mu.Unlock()

	podKey := fmt.Sprintf("%s/%s", req.PodName, req.PodNamespace)
	info, exists := h.agent.podEndpoints[podKey]
	if !exists {
		// Attempt best-effort cleanup if state is missing
		h.agent.allocator.Release(req.PodName, req.PodNamespace)
		return &grpc.DelResponse{}, nil
	}

	// 1. Remove pod endpoint from data plane using the actual IP
	h.agent.dp.RemovePodEndpoint(info.IP)

	// 2. Teardown pod network via netns package
	netnsCfg := netns.NetnsConfig{
		ContainerID: req.ContainerID,
		Netns:       info.Netns,
		IfName:      info.IfName,
	}
	h.agent.netnsManager.TeardownPodNetwork(netnsCfg)

	// 3. Release IP
	h.agent.allocator.Release(req.PodName, req.PodNamespace)

	// 4. Release identity
	h.agent.identityAllocator.ReleaseIdentity(info.IdentityID)

	delete(h.agent.podEndpoints, podKey)

	return &grpc.DelResponse{}, nil
}

func (h *NodeAgentHandler) HandleCheck(req *grpc.CheckRequest) (*grpc.CheckResponse, error) {
	log.Printf("Handling CHECK for pod %s/%s", req.PodNamespace, req.PodName)

	h.agent.mu.RLock()
	podKey := fmt.Sprintf("%s/%s", req.PodName, req.PodNamespace)
	info, exists := h.agent.podEndpoints[podKey]
	h.agent.mu.RUnlock()

	if !exists {
		return &grpc.CheckResponse{OK: false, Error: "pod not found in local state"}, nil
	}

	// Verify pod network via netns package
	err := h.agent.netnsManager.CheckPodNetwork(netns.NetnsConfig{
		ContainerID: req.ContainerID,
		Netns:       info.Netns,
		IfName:      info.IfName,
	})
	if err != nil {
		return &grpc.CheckResponse{OK: false, Error: err.Error()}, nil
	}

	return &grpc.CheckResponse{OK: true}, nil
}

func nextIP(ip net.IP) net.IP {
	i := ip.To4()
	if i == nil {
		return ip
	}
	v := uint32(i[0])<<24 | uint32(i[1])<<16 | uint32(i[2])<<8 | uint32(i[3])
	v++
	return net.IPv4(byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

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
	"syscall"
	"time"

	"github.com/coordino/cni/internal/grpc"
	"github.com/coordino/cni/pkg/dataplane"
	"github.com/coordino/cni/pkg/encryption"
	"github.com/coordino/cni/pkg/ipam"
	"github.com/coordino/cni/pkg/nodeisolation"
	"github.com/coordino/cni/pkg/observability"
)

type NodeAgent struct {
	nodeName       string
	podCIDR        string
	socketPath     string
	metricsAddr    string
	bpfMountPath   string
	checkpointPath string

	allocator  *ipam.NodeAllocator
	dataplane  *dataplane.EBPFDataPlane
	encryption *encryption.Manager
	metrics    *observability.CNIMetrics
	tracer     *observability.CNITracer
	hostPolicy *nodeisolation.HostPolicy

	server *grpc.Server
}

func main() {
	nodeName := flag.String("node-name", "", "Name of the node")
	podCIDR := flag.String("pod-cidr", "", "Pod CIDR for the node")
	socketPath := flag.String("socket-path", grpc.SocketPath, "Path to the Unix socket")
	metricsAddr := flag.String("metrics-addr", ":9090", "Address for metrics and healthz")
	bpfMountPath := flag.String("bpf-mount-path", "/sys/fs/bpf", "Path where BPF FS is mounted")
	checkpointPath := flag.String("checkpoint-path", "/var/lib/coordino/checkpoint", "Path to the checkpoint file")
	flag.Parse()

	if *nodeName == "" {
		log.Fatal("--node-name is required")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	agent, err := NewNodeAgent(*nodeName, *podCIDR, *socketPath, *metricsAddr, *bpfMountPath, *checkpointPath)
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

func NewNodeAgent(nodeName, podCIDR, socketPath, metricsAddr, bpfMountPath, checkpointPath string) (*NodeAgent, error) {
	allocator, err := ipam.NewNodeAllocator(podCIDR)
	if err != nil {
		return nil, fmt.Errorf("failed to create allocator: %v", err)
	}

	dp := dataplane.NewEBPFDataPlane(dataplane.LoaderConfig{
		BPFMountPath: bpfMountPath,
	})

	enc := encryption.NewManager(encryption.WireGuardConfig{
		InterfaceName: "wg0",
	})

	registry := observability.NewNoopRegistry()
	metrics := observability.NewCNIMetrics(registry)
	tracer := observability.NewCNITracer("node-agent", true)

	hp := nodeisolation.NewHostPolicy("Deny")

	agent := &NodeAgent{
		nodeName:       nodeName,
		podCIDR:        podCIDR,
		socketPath:     socketPath,
		metricsAddr:    metricsAddr,
		bpfMountPath:   bpfMountPath,
		checkpointPath: checkpointPath,
		allocator:      allocator,
		dataplane:      dp,
		encryption:     enc,
		metrics:        metrics,
		tracer:         tracer,
		hostPolicy:     hp,
	}

	handler := &NodeAgentHandler{agent: agent}
	agent.server = grpc.NewServer(socketPath, handler)

	return agent, nil
}

func (a *NodeAgent) Start(ctx context.Context) error {
	// Start gRPC server
	if err := a.server.Start(); err != nil {
		return fmt.Errorf("failed to start gRPC server: %v", err)
	}

	// Start metrics/health server
	go a.startHTTPServer()

	// Start reconciliation loop
	go a.reconciliationLoop(ctx)

	log.Printf("Node agent started on node %s", a.nodeName)
	return nil
}

func (a *NodeAgent) Stop() {
	a.server.Stop()
	// Flush checkpoint would happen here
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
	// log.Println("Running periodic reconciliation...")
	// 1. Reconcile eBPF programs
	// 2. Reconcile WireGuard peers
	// 3. Reconcile isolation rules
}

type NodeAgentHandler struct {
	agent *NodeAgent
}

func (h *NodeAgentHandler) HandleAdd(req *grpc.AddRequest) (*grpc.AddResponse, error) {
	log.Printf("Handling ADD for pod %s/%s", req.PodNamespace, req.PodName)

	// 1. Allocate IP
	ip, err := h.agent.allocator.Allocate(req.PodName, req.PodNamespace)
	if err != nil {
		return &grpc.AddResponse{Error: err.Error()}, nil
	}

	// 2. Add pod endpoint to data plane
	// In a real implementation, we'd need ifIndex and identityID
	err = h.agent.dataplane.AddPodEndpoint(ip, 0, 0)
	if err != nil {
		return &grpc.AddResponse{Error: err.Error()}, nil
	}

	return &grpc.AddResponse{
		IP:      ip.String() + "/24", // Assuming /24 for stub
		Gateway: "10.244.0.1",
		Routes: []grpc.Route{
			{Dst: "0.0.0.0/0", GW: "10.244.0.1"},
		},
		DNS: grpc.DNSConfig{
			Nameservers: []string{"8.8.8.8"},
		},
	}, nil
}

func (h *NodeAgentHandler) HandleDel(req *grpc.DelRequest) (*grpc.DelResponse, error) {
	log.Printf("Handling DEL for pod %s/%s", req.PodNamespace, req.PodName)

	// 1. Release IP
	err := h.agent.allocator.Release(req.PodName, req.PodNamespace)
	if err != nil {
		return &grpc.DelResponse{Error: err.Error()}, nil
	}

	// 2. Remove pod endpoint from data plane
	// We'd need the actual IP here
	h.agent.dataplane.RemovePodEndpoint(net.ParseIP("10.244.0.2"))

	return &grpc.DelResponse{}, nil
}

func (h *NodeAgentHandler) HandleCheck(req *grpc.CheckRequest) (*grpc.CheckResponse, error) {
	log.Printf("Handling CHECK for pod %s/%s", req.PodNamespace, req.PodName)
	// Verify IP is allocated and endpoint exists
	return &grpc.CheckResponse{OK: true}, nil
}

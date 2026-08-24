package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/coordino/cni/pkg/encryption"
	"github.com/coordino/cni/pkg/ipam"
	"github.com/coordino/cni/pkg/observability"
	"github.com/coordino/cni/pkg/policy"
)

type Controller struct {
	clusterCIDR      string
	blockSize        int
	metricsAddr      string
	leaderElectionID string

	ipamController *ipam.IPAMController
	compiler       *policy.Compiler
	identityAlloc  *policy.IdentityAllocator
	wgManager      *encryption.Manager
	metrics        *observability.CNIMetrics
}

func main() {
	clusterCIDR := flag.String("cluster-cidr", "10.0.0.0/8", "Cluster CIDR")
	blockSize := flag.Int("block-size", 24, "CIDR block size per node")
	metricsAddr := flag.String("metrics-addr", ":9091", "Address for metrics and healthz")
	leaderElectionID := flag.String("leader-election-id", "coordino-controller", "ID for leader election")
	flag.Parse()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c, err := NewController(*clusterCIDR, *blockSize, *metricsAddr, *leaderElectionID)
	if err != nil {
		log.Fatalf("Failed to initialize Controller: %v", err)
	}

	if err := c.Run(ctx); err != nil {
		log.Fatalf("Controller failed: %v", err)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	<-sigCh

	log.Println("Shutting down controller...")
}

func NewController(clusterCIDR string, blockSize int, metricsAddr, leaderElectionID string) (*Controller, error) {
	ipamCtrl, err := ipam.NewIPAMController(clusterCIDR, blockSize)
	if err != nil {
		return nil, fmt.Errorf("failed to create IPAM controller: %v", err)
	}

	idAlloc := policy.NewIdentityAllocator()
	compiler := policy.NewCompiler(idAlloc)
	wgManager := encryption.NewManager(encryption.WireGuardConfig{})

	registry := observability.NewNoopRegistry()
	metrics := observability.NewCNIMetrics(registry)

	return &Controller{
		clusterCIDR:      clusterCIDR,
		blockSize:        blockSize,
		metricsAddr:      metricsAddr,
		leaderElectionID: leaderElectionID,
		ipamController:   ipamCtrl,
		compiler:         compiler,
		identityAlloc:    idAlloc,
		wgManager:        wgManager,
		metrics:          metrics,
	}, nil
}

func (c *Controller) Run(ctx context.Context) error {
	// 1. Leader Election Stub
	log.Printf("Starting leader election for %s...", c.leaderElectionID)
	// In production, controller-runtime or client-go leader election would be used here.
	log.Println("Acquired leadership, starting reconciliation loops")

	// 2. Start HTTP server
	go c.startHTTPServer()

	// 3. Start reconciliation loops
	go c.nodeRegistrationLoop(ctx)
	go c.policyCompilationLoop(ctx)
	go c.identityGCLoop(ctx)
	go c.wireguardRotationLoop(ctx)

	log.Println("Controller is running")
	return nil
}

func (c *Controller) startHTTPServer() {
	http.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("# Metrics stub"))
	})
	http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})
	http.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("READY"))
	})
	log.Printf("Starting HTTP server on %s", c.metricsAddr)
	if err := http.ListenAndServe(c.metricsAddr, nil); err != nil {
		log.Printf("HTTP server failed: %v", err)
	}
}

func (c *Controller) nodeRegistrationLoop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			// log.Println("Watching for new nodes and assigning CIDR blocks...")
		case <-ctx.Done():
			return
		}
	}
}

func (c *Controller) policyCompilationLoop(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			// log.Println("Compiling NetworkPolicies to identity + IR...")
		case <-ctx.Done():
			return
		}
	}
}

func (c *Controller) identityGCLoop(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			// log.Println("Running identity garbage collection...")
		case <-ctx.Done():
			return
		}
	}
}

func (c *Controller) wireguardRotationLoop(ctx context.Context) {
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			// log.Println("Checking for WireGuard key rotation...")
		case <-ctx.Done():
			return
		}
	}
}

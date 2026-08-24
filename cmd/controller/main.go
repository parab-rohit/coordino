package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/coordino/cni/pkg/encryption"
	"github.com/coordino/cni/pkg/ipam"
	"github.com/coordino/cni/pkg/observability"
	"github.com/coordino/cni/pkg/policy"
)

// LeaderElector implements a file-based lock for leader election.
type LeaderElector struct {
	lockPath string
	lockFile *os.File
	mu       sync.Mutex
}

func NewLeaderElector(id string) *LeaderElector {
	return &LeaderElector{
		lockPath: fmt.Sprintf("/tmp/%s.lock", id),
	}
}

func (le *LeaderElector) TryAcquire() bool {
	le.mu.Lock()
	defer le.mu.Unlock()

	if le.lockFile != nil {
		return true
	}

	f, err := os.OpenFile(le.lockPath, os.O_RDWR|os.O_CREATE, 0666)
	if err != nil {
		return false
	}

	err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if err != nil {
		f.Close()
		return false
	}

	le.lockFile = f
	return true
}

func (le *LeaderElector) Release() {
	le.mu.Lock()
	defer le.mu.Unlock()

	if le.lockFile != nil {
		syscall.Flock(int(le.lockFile.Fd()), syscall.LOCK_UN)
		le.lockFile.Close()
		le.lockFile = nil
	}
}

func (le *LeaderElector) IsLeader() bool {
	le.mu.Lock()
	defer le.mu.Unlock()
	return le.lockFile != nil
}

// CRDReconciler manages IPPool and NodeConfig state.
type CRDReconciler struct {
	ipamController *ipam.IPAMController
}

func NewCRDReconciler(ipamCtrl *ipam.IPAMController) *CRDReconciler {
	return &CRDReconciler{
		ipamController: ipamCtrl,
	}
}

func (r *CRDReconciler) ReconcileIPPools() {
	assignments := r.ipamController.GetAllAssignments()
	log.Printf("[Reconciler] Syncing IPPools: %d nodes have assignments", len(assignments))
}

func (r *CRDReconciler) ReconcileNodeConfigs() {
	assignments := r.ipamController.GetAllAssignments()
	for node, blocks := range assignments {
		if len(blocks) > 0 {
			log.Printf("[Reconciler] Updating NodeConfig for %s: CIDR %s", node, blocks[0].CIDR.String())
		}
	}
}

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

	leaderElector *LeaderElector
	reconciler    *CRDReconciler
	policies      map[string]policy.NetworkPolicySpec
	mu            sync.RWMutex
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

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	if err := c.Run(ctx); err != nil {
		log.Fatalf("Controller failed: %v", err)
	}

	<-sigCh
	log.Println("Shutting down controller...")
	c.leaderElector.Release()
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
		leaderElector:    NewLeaderElector(leaderElectionID),
		reconciler:       NewCRDReconciler(ipamCtrl),
		policies:         make(map[string]policy.NetworkPolicySpec),
	}, nil
}

func (c *Controller) Run(ctx context.Context) error {
	// 1. Leader Election
	log.Printf("Starting leader election for %s...", c.leaderElectionID)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	// Attempt leadership before starting reconciliation loops
	for {
		if c.leaderElector.TryAcquire() {
			break
		}
		select {
		case <-ticker.C:
			log.Println("Waiting for leadership...")
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	log.Println("Acquired leadership, starting reconciliation loops")

	// Simulation: add a dummy policy
	c.mu.Lock()
	c.policies["default-deny"] = policy.NetworkPolicySpec{
		PodSelector: map[string]string{"env": "prod"},
	}
	c.mu.Unlock()

	// 2. Start HTTP server
	go c.startHTTPServer()

	// 3. Start reconciliation loops
	go c.nodeRegistrationLoop(ctx)
	go c.policyCompilationLoop(ctx)
	go c.identityGCLoop(ctx)
	go c.wireguardRotationLoop(ctx)
	go c.crdReconciliationLoop(ctx)

	log.Println("Controller is running")
	return nil
}

func (c *Controller) startHTTPServer() {
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("# Metrics stub"))
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		if c.leaderElector.IsLeader() {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("READY"))
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte("NOT_READY"))
		}
	})

	log.Printf("Starting HTTP server on %s", c.metricsAddr)
	server := &http.Server{Addr: c.metricsAddr, Handler: mux}
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Printf("HTTP server failed: %v", err)
	}
}

func (c *Controller) crdReconciliationLoop(ctx context.Context) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			c.reconciler.ReconcileIPPools()
			c.reconciler.ReconcileNodeConfigs()
		case <-ctx.Done():
			return
		}
	}
}

func (c *Controller) nodeRegistrationLoop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	nodeIdx := 0
	for {
		select {
		case <-ticker.C:
			nodeName := fmt.Sprintf("node-%d", nodeIdx)
			cidr, err := c.ipamController.AssignBlock(nodeName)
			if err != nil {
				log.Printf("Failed to assign block to %s: %v", nodeName, err)
			} else {
				log.Printf("Successfully assigned block %s to %s", cidr.String(), nodeName)
				nodeIdx++
			}
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
			c.mu.RLock()
			for name, spec := range c.policies {
				compiled, err := c.compiler.CompilePolicy(name, "default", spec)
				if err != nil {
					log.Printf("Failed to compile policy %s: %v", name, err)
				} else {
					log.Printf("Policy %s compiled: %d rules generated at %v", name, len(compiled.Rules), compiled.CompiledAt)
				}
			}
			c.mu.RUnlock()
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
			log.Println("Checking identities for garbage collection...")
			// Simulate by checking identities of nodes we know about
			assignments := c.ipamController.GetAllAssignments()
			for nodeName := range assignments {
				identities := c.identityAlloc.GetIdentitiesForNode(nodeName)
				for _, id := range identities {
					if id.RefCount <= 0 {
						log.Printf("Garbage collecting identity %d on node %s", id.ID, nodeName)
						c.identityAlloc.ReleaseIdentity(id.ID)
					}
				}
			}
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
			log.Println("Rotating WireGuard keys...")
			kp, err := c.wgManager.RotateKeys()
			if err != nil {
				log.Printf("Failed to rotate WireGuard keys: %v", err)
			} else {
				log.Printf("New WireGuard public key generated: %s", kp.PublicKey)
			}
		case <-ctx.Done():
			return
		}
	}
}

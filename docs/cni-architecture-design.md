# Kubernetes CNI Plugin — Architecture & Design Document

**Status:** Draft v1
**Owners:** SRE / Platform Engineering
**Language:** Go

---

## 1. Purpose & Requirements

### 1.1 Functional Requirements
- Kubernetes-native CNI plugin implementing the CNI spec (ADD/DEL/CHECK)
- IPAM (IP address management) for pod networking
- Kubernetes `NetworkPolicy` enforcement
- Encryption-in-transit (optional, toggleable) for pod-to-pod traffic
- Node isolation (pod-to-host and node-to-node control-plane isolation)
- Built-in observability (metrics, tracing, flow logs)

### 1.2 Non-Functional Requirements (target SLOs)

| Requirement | Target |
|---|---|
| Cluster scale | 5,000 nodes |
| Pod density | 110 pods/node (550,000 pods cluster-wide) |
| Pod network-ready latency | p99 < 250ms |
| Churn tolerance | Sustained mass scale-up/down (e.g. 500 pods/node/min) without SLO breach |
| Control-plane outage behavior | Existing pod connectivity unaffected; data plane degrades statelessly |
| Policy enforcement | Full Kubernetes NetworkPolicy semantics |
| Encryption | Optional, per-namespace or cluster-wide toggle |
| Node isolation | Pod→host and node→node control-plane isolation |
| Observability | Per-stage latency, policy reconcile lag, flow-level visibility |

### 1.3 Explicit Non-Goals (v1)
- Multi-cluster mesh / cluster federation (future work, see §11)
- L7 policy (HTTP/gRPC-aware) — reserved for v2
- Windows node support

---

## 2. High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                 Control Plane (leader-elected)                 │
│  ┌────────────────┐  ┌──────────────────┐  ┌───────────────┐ │
│  │ IPAM Controller │  │ Policy Controller │  │ CRD Store      │ │
│  │ (node CIDR      │  │ (NetworkPolicy →  │  │ (IPPool,       │ │
│  │  block assign)  │  │  identity + IR)   │  │  NodeConfig,   │ │
│  │                  │  │                   │  │  Identity,     │ │
│  │                  │  │                   │  │  NodeIsolation)│ │
│  └────────────────┘  └──────────────────┘  └───────────────┘ │
└─────────────────────────────────────────────────────────────┘
                              │ watch/reconcile (K8s API, informers)
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                 Per-Node Agent (DaemonSet)                     │
│  ┌───────────┐  ┌────────────┐  ┌──────────────────────────┐ │
│  │ CNI binary │  │ Node Agent │  │ eBPF Loader / Programmer   │ │
│  │ (kubelet   │→ │ (local     │→ │ (identity maps, policy     │ │
│  │  exec'd)   │  │  socket)   │  │  maps, WireGuard peers)    │ │
│  └───────────┘  └────────────┘  └──────────────────────────┘ │
│         local disk checkpoint (BadgerDB) ── survives restart   │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
                Kernel Data Plane (per node)
     veth + eBPF (tc/XDP hooks), pinned maps, WireGuard (wg0)
```

**Core principle:** control plane decides *intent*; node agent + kernel enforce *state*. The kernel-resident state (pinned eBPF maps, WireGuard config) is the source of truth for existing traffic — the control plane and agent process are both disposable relative to it.

---

## 3. Component Design

### 3.1 CNI Binary (`/cmd/cni-plugin`)
- Thin, static Go binary, exec'd synchronously by kubelet on pod ADD/DEL/CHECK
- Responsibilities: create veth pair, exec into pod netns, call node agent over local Unix domain socket, apply returned IP/route config
- No business logic, no API server calls, no eBPF operations — all delegated to node agent
- Target: <30ms of the 250ms budget

### 3.2 Node Agent (`/cmd/node-agent`, DaemonSet)
- Long-running daemon, one per node
- Owns: local IPAM allocator, eBPF program lifecycle, WireGuard peer config, policy map programming, local state checkpointing
- Exposes: Unix socket (for CNI binary), Prometheus `/metrics`, gRPC health/readiness
- Loads eBPF programs **once at startup** (or on verified upgrade), not per pod
- Checkpoints reconciled state to embedded KV store (BadgerDB) after every successful reconcile

### 3.3 Controller (`/cmd/controller`, leader-elected Deployment, 3 replicas)
- IPAM Controller: assigns /24 CIDR blocks to nodes on registration, tracks via `IPPool`/`NodeConfig` CRDs
- Policy Controller: watches `NetworkPolicy`, resolves label selectors, assigns/reuses security identities, compiles to intermediate representation (IR), publishes per-node-relevant IR slices
- Does **not** sit in the pod-creation critical path — node agents already hold what they need locally

### 3.4 CRDs

| CRD | Purpose |
|---|---|
| `IPPool` | Cluster-wide pod CIDR and allocation state |
| `NodeConfig` | Per-node assigned block, WireGuard pubkey, agent version |
| `Identity` | Label-set hash → identity ID mapping (Cilium-style security identity) |
| `PolicyIR` | Compiled per-identity policy rules, filtered per-node |
| `NodeIsolationPolicy` | Platform-owned pod↔host and node↔node isolation rules |

---

## 4. IPAM Design

- **Cluster CIDR**: `10.0.0.0/8`, split into **/24 blocks per node** (254 usable IPs vs. 110 pod requirement — headroom for hostNetwork pods, GC races, DaemonSet overhead)
- **Model**: node-scoped allocation. Controller assigns block to node **at node registration**, before any pod scheduling — this removes the API server from the pod-creation hot path entirely
- **Local allocation**: node agent runs an in-memory bitmap allocator over its assigned block; pod IP assignment is a local, sub-millisecond operation
- **Overflow handling**: if a node's block is exhausted (unlikely at 254/110 ratio but possible with high hostNetwork/DaemonSet density), agent requests a secondary block from the controller asynchronously — this path is allowed to be slower since it's rare
- **Leak prevention**: 
  - IP released synchronously on pod DEL
  - Periodic reconciliation sweep (every 60s) comparing kubelet's actual pod list against allocated-IP records, releasing orphaned IPs (handles agent-crash-during-DEL)

---

## 5. Data Plane Design

### 5.1 Technology Choice: eBPF (primary), iptables (fallback)
- eBPF programs attached at tc/XDP hooks on veth and host interfaces
- In-kernel policy enforcement avoids netfilter/iptables O(n) rule traversal — required to meet p99 latency and churn targets at 550,000-pod scale
- Data-plane layer is built behind an internal interface so an iptables fallback can be substituted on kernels lacking required eBPF features (older on-prem/regulated environments)
- Minimum kernel version requirement to be pinned during implementation (BTF/CO-RE support required)

### 5.2 Identity-Based Policy Model
- Pods are resolved to a **security identity** — a hash of the pod's relevant label set — not evaluated pod-by-pod
- Pods sharing identical labels share one identity; policy is compiled and stored per-identity-pair, not per-pod-pair
- This bounds the cost of Deployment scale events: scaling 100→10,000 replicas is **one identity**, O(1) policy cost, not O(n) recomputation
- eBPF policy maps keyed by `(src_identity, dst_identity) → verdict`

### 5.3 Routing Mode
- Pluggable routing backend, selected per-environment:
  - **BGP-based native routing** (default for on-prem/bare metal) — no encapsulation overhead
  - **VXLAN/Geneve overlay** (portable fallback) — used where underlay BGP peering isn't available
  - **Cloud-native VPC mode** (ENI/alias-IP style) — pluggable backend for managed cloud environments
- Routing backend must not be hardcoded into the core agent — implemented as a strategy interface

---

## 6. NetworkPolicy Enforcement Pipeline

```
NetworkPolicy CRD (watch)
   → label selector resolution (cached, incremental via informer)
   → identity assignment (new label-set → new identity; existing → ref-counted reuse)
   → policy compiled to IR per-identity
   → node agents pull only identities present on their node
   → IR compiled to eBPF map entries (identity-pair → verdict)
```

- Selector resolution must be cached and incrementally updated — full recomputation on every pod event is the primary cause of policy-controller meltdown during mass rollouts
- Policy tiers (priority order, highest first):
  1. `NodeIsolationPolicy` (platform-owned, non-overridable by tenants)
  2. Platform-mandated allow rules (DNS, monitoring scrape)
  3. Tenant `NetworkPolicy` rules
- Default posture (deny-by-default vs allow-by-default) must be explicit and must hold consistently through control-plane restarts — document as a fail-closed design (existing enforcement holds; new policy just doesn't propagate) rather than fail-open

---

## 7. Encryption in Transit

- **Mechanism**: WireGuard (chosen over IPsec for simpler kernel interface, no SA/SPI management overhead)
- **Key management**: controller generates/rotates per-node keypairs; private key never leaves the node; public keys distributed via `NodeConfig` CRD
- **Peer provisioning**: node agent provisions **all peers proactively at startup** (not lazily on first cross-node packet) — keeps WireGuard off the pod-ready critical path
- **Toggle**: configurable cluster-wide or per-namespace via CRD flag, since always-on WireGuard costs ~3-5% throughput

---

## 8. Node Isolation

Two distinct isolation surfaces:

1. **Pod-to-host isolation**: default-deny from pod netns to node host namespace, except explicitly allowlisted paths (kubelet health checks, node-exporter scrape) — enforced via eBPF hook at the veth's host side
2. **Node-to-node control-plane isolation**: node agents restricted (via host-level eBPF/tc rules) to reaching only the K8s API server and WireGuard peers — prevents a compromised pod from pivoting through the host network stack

Both modeled as `NodeIsolationPolicy` CRD, platform-team-owned, enforced as the highest-priority policy tier.

---

## 9. Stateless Degradation on Control-Plane Outage

Concrete mechanisms (not aspirational — each maps to a specific implementation choice):

| Mechanism | Effect |
|---|---|
| eBPF maps pinned to `/sys/fs/bpf` | Agent crash/restart does not unplumb existing kernel rules |
| Node agent state checkpointed to local disk (BadgerDB) on every reconcile | Agent restart loads from disk first, diffs against live map state, before touching API server |
| IPAM allocation is local-only for already-assigned blocks | New pods can still get IPs and be wired up with API server and controller both down |
| WireGuard peer config persisted locally | Existing encrypted paths continue functioning without control-plane reachability |

**Explicit failure mode during control-plane outage:**
- Continues working: existing pod connectivity, existing policy enforcement, new pod IP allocation on already-assigned node blocks
- Paused until recovery: new NetworkPolicy propagation, new node onboarding (fresh CIDR block assignment), new WireGuard peer distribution for brand-new nodes

---

## 10. Latency Budget (pod network-ready, p99 < 250ms)

| Stage | Budget | Design lever |
|---|---|---|
| kubelet → CNI binary exec | 5ms | Static binary, no dynamic linking |
| CNI binary → node agent (local socket) | 2ms | Unix domain socket |
| IP allocation | 3ms | In-memory bitmap, zero API calls |
| veth create + netns wiring | 15ms | Direct netlink, no shell-out |
| eBPF map programming | 30ms | Program pre-loaded at agent boot; only map writes per pod |
| Route/neighbor table update | 10ms | Batched netlink |
| WireGuard peer confirm | 5ms | Peers provisioned proactively, not on-demand |
| gRPC/socket response return | 5ms | — |
| **Steady-state total** | **~75ms** | ~175ms headroom for GC pauses, scheduler/CPU contention under churn |

Each stage must be independently traced (OTel spans) — the headroom, not the steady-state number, is what determines whether p99 holds under churn.

---

## 11. Observability

### 11.1 Metrics (Prometheus, per node agent)
```
cni_pod_ready_duration_seconds{stage=...}          (histogram, per-stage from §10)
cni_policy_reconcile_lag_seconds                     (K8s event → eBPF map write)
cni_ipam_block_utilization_ratio{node}
cni_ebpf_map_entries{map_name}
cni_conntrack_utilization_ratio
cni_wireguard_handshake_failures_total{peer}
cni_agent_bpf_map_write_errors_total
```

### 11.2 Tracing
- One OTel span per CNI ADD/DEL, child span per latency-budget stage
- Enables isolating which node and which stage drags cluster-wide p99

### 11.3 Flow Visibility
- eBPF ring buffer exporting `(src_identity, dst_identity, verdict, matched_policy)` per sampled flow
- Primary tool for NetworkPolicy debugging and audit compliance

### 11.4 SLO-Driven Alerting
- Burn-rate alert on `cni_pod_ready_duration_seconds` p99 vs. 250ms target
- IPAM exhaustion **leading indicator** (block >80% utilized) — before scheduling failures occur
- Policy reconcile lag trend during mass rollout — early warning of controller falling behind churn
- Node agent crash-loop detection distinct from generic pod restart alerts

---

## 12. Rollout & Upgrade Strategy

- DaemonSet `maxUnavailable: 1`
- Agent upgrade must **attach to already-pinned eBPF maps**, not tear down and reprogram — avoids dropping existing flows during rolling upgrade
- Canary new agent version on a labeled node subset, verify golden signals (§11) before progressive rollout
- Documented, tested rollback path required before any version is marked GA-eligible internally — data-plane state compatibility between versions must be explicitly verified

---

## 13. Package Layout

```
/cmd
  /cni-plugin        → thin binary, exec'd by kubelet
  /node-agent         → daemon: IPAM, eBPF programmer, WireGuard mgmt
  /controller         → leader-elected: IPAM allocation, policy compiler
/pkg
  /ipam
    node_allocator.go      → local bitmap allocator (in-memory)
    controller.go          → cluster-scoped block assignment (CRD-backed)
  /policy
    identity.go             → label-set → identity ID resolution
    compiler.go              → NetworkPolicy CRD → IR
    ebpf_writer.go           → IR → eBPF map entries
  /dataplane
    /ebpf                    → C source + go:generate bpf2go bindings
    loader.go                → per-node program load/attach
    maps.go                  → pinned map management
  /encryption
    wireguard.go             → key mgmt, peer config, CRD-based pubkey distribution
  /nodeisolation
    host_policy.go           → node-to-node / pod-to-host default rules
  /observability
    metrics.go               → Prometheus
    tracing.go                → OTel spans for ADD/DEL path
    flowlog.go                → ring-buffer flow export
  /apis
    /v1alpha1                → IPPool, NodeConfig, Identity, PolicyIR, NodeIsolationPolicy
/internal/grpc              → cni-plugin ↔ node-agent local socket protocol
```

---

## 14. Key Architectural Decisions (explicit record)

| # | Decision | Chosen | Rejected alternative | Rationale |
|---|---|---|---|---|
| 1 | IPAM scope | Node-scoped blocks | Cluster-scoped per-pod allocation | Removes API server from pod-creation hot path |
| 2 | Data plane | eBPF (iptables fallback) | iptables/IPVS only | O(1)-ish scaling vs O(n) rule traversal at 550k-pod scale |
| 3 | Policy model | Identity-based | Per-pod-pair rules | Bounds churn cost to O(unique label sets), not O(pods) |
| 4 | Routing | Pluggable (BGP/overlay/cloud-native) | Hardcoded single mode | Portability across on-prem/cloud without fork |
| 5 | Encryption | WireGuard | IPsec | Simpler kernel interface, less operational overhead |
| 6 | Failure mode | Fail-closed, stateless degradation | Fail-open | Existing traffic/policy must survive control-plane outage |
| 7 | eBPF program lifecycle | Load once at agent boot, map writes per pod | Load/attach per pod | Verifier pass is the slow/unpredictable step; must stay off hot path |

---

## 15. Future Work (out of scope for v1)
- Multi-cluster mesh (cross-cluster pod routing via BGP peering or shared overlay)
- L7-aware policy (HTTP/gRPC introspection)
- Namespace-scoped IPAM pools for stronger multi-tenancy
- Admission webhook to block overly permissive tenant NetworkPolicies

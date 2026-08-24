# Kubernetes CNI Plugin — Implementation Task List

Companion to `cni-architecture-design.md`. Organized into phases; each phase should be independently demoable and testable before moving to the next. Task IDs are stable references for tracking (e.g., in issues/tickets).

---

## Phase 0 — Foundations & Environment

- [ ] **0.1** Stand up dev cluster(s): a small kind/k3d cluster for fast iteration, and a scale-test cluster (target: subset large enough to extrapolate to 5,000 nodes, e.g. 200–500 nodes)
- [ ] **0.2** Pin minimum supported kernel version (BTF/CO-RE requirement) and document in repo
- [x] **0.3** Set up Go module structure per package layout (§13 of design doc)
- [ ] **0.4** Set up CI: lint, unit tests, `go vet`, eBPF program compile check (`bpf2go`)
- [x] **0.5** Define CRD schemas (`IPPool`, `NodeConfig`, `Identity`, `PolicyIR`, `NodeIsolationPolicy`) and generate deepcopy/client code
- [ ] **0.6** Set up local Prometheus + Grafana + Jaeger/Tempo stack for dev observability

---

## Phase 1 — Minimal Viable CNI (no policy, no encryption)

Goal: pods get IPs and can talk to each other. No NetworkPolicy, no WireGuard yet.

### 1.1 CNI Binary
- [x] Implement CNI spec ADD/DEL/CHECK handlers
- [ ] Implement veth pair creation and netns wiring (netlink, no shell-out)
- [x] Implement Unix domain socket client to node agent
- [ ] Static binary build, verify <30ms execution time in isolation

### 1.2 Node Agent — IPAM
- [x] Implement in-memory bitmap allocator for a /24 block
- [x] Implement Unix domain socket server (CNI binary ↔ agent protocol)
- [x] Implement local IP allocation/release on ADD/DEL
- [x] Implement periodic reconciliation sweep (orphaned IP GC, every 60s)
- [ ] Implement local disk checkpoint (BadgerDB) of allocation state

### 1.3 Controller — IPAM
- [ ] Implement leader election (controller-runtime)
- [x] Implement node registration watch → CIDR block assignment
- [ ] Implement `IPPool`/`NodeConfig` CRD reconciliation loop
- [x] Implement block overflow/secondary-block-request handling

### 1.4 Routing (baseline)
- [ ] Implement BGP-based native routing backend (e.g. via GoBGP or Bird integration)
- [ ] Implement VXLAN overlay backend (fallback/portable mode)
- [ ] Implement routing backend as pluggable strategy interface
- [ ] Validate pod-to-pod connectivity across nodes in both modes

### 1.5 Phase 1 Exit Criteria
- [ ] Pods on different nodes can reach each other with no policy applied
- [ ] Basic `cni_pod_ready_duration_seconds` metric emitted (total only, no per-stage yet)
- [ ] Passes conformance subset: pod IP uniqueness, no IP leak after 1,000 create/delete cycles

---

## Phase 2 — Data Plane (eBPF) & Identity Model

Goal: replace/augment routing with eBPF programs; establish identity-based model as foundation for policy.

### 2.1 eBPF Program Development
- [ ] Write core eBPF C program: veth ingress/egress hooks (tc)
- [ ] Write eBPF program: identity lookup map (pod IP → identity ID)
- [ ] Set up `bpf2go` code generation pipeline
- [ ] Implement pinned map management (`/sys/fs/bpf`) — survive agent restart

### 2.2 Node Agent — eBPF Loader
- [ ] Implement program load/attach at agent startup (once, not per pod)
- [ ] Implement "attach to existing pinned maps" path for agent upgrade (no reprogram)
- [ ] Implement per-pod map entry write (identity assignment) on CNI ADD
- [ ] Implement map entry cleanup on CNI DEL

### 2.3 Identity Resolution
- [x] Implement label-set hashing → identity ID assignment (controller-side)
- [x] Implement identity ref-counting (reuse across pods with identical labels)
- [ ] Implement `Identity` CRD watch on node agent (filtered to node's present identities)
- [ ] Implement incremental (not full-recompute) selector resolution cache

### 2.4 iptables Fallback
- [x] Implement iptables-based data plane behind same internal interface
- [ ] Implement kernel feature detection → auto-select eBPF vs iptables at agent startup

### 2.5 Phase 2 Exit Criteria
- [ ] All pod traffic flows through eBPF data plane (or verified iptables fallback)
- [ ] Identity assigned correctly for pods with shared and distinct label sets
- [ ] Agent restart does not drop existing traffic (manual chaos test)

---

## Phase 3 — NetworkPolicy Enforcement

### 3.1 Policy Controller
- [ ] Implement `NetworkPolicy` CRD watch/informer
- [ ] Implement label selector → identity resolution pipeline
- [ ] Implement IR compiler (NetworkPolicy → per-identity rule IR)
- [ ] Implement per-node IR filtering/publication (`PolicyIR` CRD)

### 3.2 Node Agent — Policy Enforcement
- [x] Implement IR → eBPF policy map compiler (`identity-pair → verdict`)
- [ ] Implement policy tiering: `NodeIsolationPolicy` > platform-mandated > tenant policy
- [ ] Implement default-deny/allow posture, verify consistent across agent restart
- [ ] Implement DNS and monitoring-scrape platform-mandated allow rules

### 3.3 Testing
- [ ] Kubernetes NetworkPolicy conformance test suite (upstream e2e tests)
- [ ] Policy churn test: apply/remove 1,000 policies, measure reconcile lag
- [ ] Verify O(1) cost of Deployment scale event (100→10,000 replicas, same identity)

### 3.4 Phase 3 Exit Criteria
- [ ] Passes upstream NetworkPolicy conformance suite
- [ ] Policy reconcile lag metric stays bounded under mass rollout test
- [ ] Fail-closed behavior verified: kill controller mid-policy-change, confirm existing policy holds

---

## Phase 4 — Encryption in Transit

- [ ] Implement WireGuard keypair generation/rotation (controller-side)
- [ ] Implement pubkey distribution via `NodeConfig` CRD
- [ ] Implement node agent WireGuard interface (`wg0`) provisioning
- [ ] Implement proactive peer provisioning at agent startup (all nodes, not lazy)
- [ ] Implement cross-node traffic routing through `wg0`
- [ ] Implement cluster-wide and per-namespace encryption toggle (CRD flag)
- [ ] Benchmark throughput tax (target: confirm ~3-5% overhead, not more)
- [ ] Test key rotation with zero connection drop

---

## Phase 5 — Node Isolation

- [ ] Implement `NodeIsolationPolicy` CRD and controller reconciliation
- [ ] Implement pod-to-host default-deny eBPF hook (veth host-side)
- [ ] Implement allowlist: kubelet health checks, node-exporter scrape
- [ ] Implement node-to-node control-plane isolation (host-level eBPF/tc rules restricting agent egress to API server + WireGuard peers)
- [ ] Verify tenant NetworkPolicy cannot override `NodeIsolationPolicy` (priority tier test)
- [ ] Penetration test: attempt pod → host pivot, confirm blocked

---

## Phase 6 — Observability

### 6.1 Metrics
- [ ] Instrument per-stage `cni_pod_ready_duration_seconds` (all 8 stages from design doc §10)
- [ ] Implement `cni_policy_reconcile_lag_seconds`
- [ ] Implement `cni_ipam_block_utilization_ratio`
- [ ] Implement `cni_ebpf_map_entries`
- [ ] Implement `cni_conntrack_utilization_ratio`
- [ ] Implement `cni_wireguard_handshake_failures_total`
- [ ] Implement `cni_agent_bpf_map_write_errors_total`

### 6.2 Tracing
- [ ] Instrument OTel spans for full CNI ADD/DEL path
- [ ] Wire per-stage child spans matching latency budget table
- [ ] Validate trace propagation from CNI binary through node agent

### 6.3 Flow Logs
- [ ] Implement eBPF ring buffer flow export (src identity, dst identity, verdict, matched policy)
- [ ] Implement userspace consumer/exporter (Hubble-style) for flow logs
- [ ] Build basic query/CLI tool for flow log inspection

### 6.4 Dashboards & Alerts
- [ ] Build Grafana dashboard: pod-ready latency breakdown by stage
- [ ] Build Grafana dashboard: policy reconcile lag over time
- [ ] Build Grafana dashboard: IPAM utilization per node/cluster
- [ ] Implement burn-rate alert: p99 pod-ready latency vs 250ms SLO
- [ ] Implement leading-indicator alert: IPAM block >80% utilized
- [ ] Implement alert: node agent crash-loop
- [ ] Implement alert: policy reconcile lag trending up during rollout

---

## Phase 7 — Scale & Chaos Testing

- [ ] Load test: sustained churn at 500 pods/node/min across test cluster, measure p99
- [ ] Scale test: extrapolate/validate behavior toward 5,000-node, 550,000-pod target (staged: 500 → 1,500 → 5,000 nodes)
- [ ] Chaos test: kill controller (all replicas) for 30 min, verify existing pod connectivity and policy hold
- [ ] Chaos test: kill node agent mid-reconcile, verify checkpoint recovery and no dropped flows
- [ ] Chaos test: simulate API server unreachable, verify new pod scheduling still succeeds (existing node blocks)
- [ ] Soak test: 72-hour run under moderate churn, watch for conntrack/memory leaks
- [ ] Validate IP leak rate is zero over 100,000 create/delete cycles

---

## Phase 8 — Rollout & Upgrade Tooling

- [ ] Implement DaemonSet upgrade path: attach to pinned maps, no reprogram/flow-drop
- [ ] Build canary rollout tooling (labeled node subset, golden-signal gating)
- [ ] Document and test rollback procedure (version compatibility matrix for data-plane state)
- [ ] Write runbook: what breaks / what doesn't during control-plane outage (§9 of design doc)
- [ ] Write runbook: diagnosing p99 latency regressions using per-stage traces

---

## Phase 9 — Documentation & Handoff

- [ ] Architecture doc finalized and reviewed (this companion doc)
- [ ] Operator runbooks: upgrade, rollback, incident response for each major failure mode
- [ ] CRD reference documentation
- [ ] Metrics/alerts reference (what each metric means, what action to take)
- [ ] Onboarding guide for new SRE/on-call engineers

---

## Cross-Cutting / Ongoing
- [ ] Security review of eBPF programs (verifier constraints, privilege model)
- [ ] Security review of WireGuard key management (rotation, storage)
- [ ] Dependency/CVE scanning in CI
- [ ] Performance regression gate in CI (fail build if synthetic p99 benchmark regresses)

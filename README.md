# Coordino CNI Plugin

A Kubernetes-native CNI plugin implementing the CNI spec (ADD/DEL/CHECK) with IPAM, NetworkPolicy enforcement, encryption-in-transit, node isolation, and built-in observability.

## Architecture

See [docs/cni-architecture-design.md](docs/cni-architecture-design.md) for the full architecture and design document, and [docs/cni-implementation-tasks.md](docs/cni-implementation-tasks.md) for the phased implementation plan.

### Components

| Component | Path | Description |
|---|---|---|
| **CNI Binary** | `cmd/cni-plugin` | Thin static binary exec'd by kubelet on pod ADD/DEL/CHECK |
| **Node Agent** | `cmd/node-agent` | Per-node daemon (DaemonSet): local IPAM, eBPF lifecycle, WireGuard, policy |
| **Controller** | `cmd/controller` | Leader-elected: IPAM block allocation, policy compilation, identity management |

### Package Layout

```
/cmd
  /cni-plugin        → thin binary, exec'd by kubelet
  /node-agent         → daemon: IPAM, eBPF programmer, WireGuard mgmt
  /controller         → leader-elected: IPAM allocation, policy compiler
/pkg
  /apis/v1alpha1      → CRD types: IPPool, NodeConfig, Identity, PolicyIR, NodeIsolationPolicy
  /ipam               → node-local bitmap allocator + cluster-scoped block assignment
  /policy             → identity resolution, NetworkPolicy→IR compiler, eBPF map writer
  /dataplane          → eBPF program loader, pinned map management
  /encryption         → WireGuard key mgmt, peer config
  /nodeisolation      → pod-to-host and node-to-node isolation rules
  /observability      → Prometheus metrics, OTel tracing, flow logs
/internal/grpc        → CNI binary ↔ node agent Unix socket protocol
/docs                 → Architecture and implementation documentation
```

## Key Design Decisions

| Decision | Chosen | Rationale |
|---|---|---|
| IPAM scope | Node-scoped /24 blocks | Removes API server from pod-creation hot path |
| Data plane | eBPF (iptables fallback) | O(1) scaling vs O(n) at 550k-pod scale |
| Policy model | Identity-based | Bounds churn to O(unique label sets), not O(pods) |
| Routing | Pluggable (BGP/overlay/cloud) | Portability without fork |
| Encryption | WireGuard | Simpler kernel interface than IPsec |
| Failure mode | Fail-closed, stateless degradation | Existing traffic survives control-plane outage |

## Target SLOs

- **Cluster scale**: 5,000 nodes, 110 pods/node (550,000 pods)
- **Pod network-ready latency**: p99 < 250ms (steady-state ~75ms)
- **Churn tolerance**: 500 pods/node/min sustained
- **Control-plane outage**: existing connectivity unaffected

## Building

```bash
# Build all binaries
go build ./...

# Run tests
go test ./...

# Run vet
go vet ./...
```

## Development

Requirements:
- Go 1.21+
- Linux kernel with BTF/CO-RE support (for eBPF data plane)
- WireGuard kernel module (for encryption)

## License

Apache License 2.0

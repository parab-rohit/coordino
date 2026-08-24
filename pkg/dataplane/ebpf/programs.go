// Package ebpf contains eBPF C programs and generated Go bindings for the coordino CNI plugin.
package ebpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang CNI ./cni.c

// ProgramInfo holds metadata about an eBPF program.
type ProgramInfo struct {
	Name        string
	Type        string // e.g. "tc", "xdp"
	AttachPoint string
	PinnedPath  string
}

// Programs lists the eBPF programs used by the dataplane.
type Programs struct {
	TCIngress  ProgramInfo
	TCEgress   ProgramInfo
	XDPIngress ProgramInfo
}

// DefaultPrograms returns the default eBPF program configuration.
func DefaultPrograms() Programs {
	return Programs{
		TCIngress: ProgramInfo{
			Name:        "cni_tc_ingress",
			Type:        "tc",
			AttachPoint: "ingress",
			PinnedPath:  "/sys/fs/bpf/coordino/tc_ingress",
		},
		TCEgress: ProgramInfo{
			Name:        "cni_tc_egress",
			Type:        "tc",
			AttachPoint: "egress",
			PinnedPath:  "/sys/fs/bpf/coordino/tc_egress",
		},
		XDPIngress: ProgramInfo{
			Name:        "cni_xdp_ingress",
			Type:        "xdp",
			AttachPoint: "ingress",
			PinnedPath:  "/sys/fs/bpf/coordino/xdp_ingress",
		},
	}
}

package main

import (
	"encoding/json"
	"io"
	"os"
	"strings"

	"github.com/coordino/cni/internal/grpc"
)

// CNIConfig represents the CNI configuration passed via stdin.
type CNIConfig struct {
	CNIVersion string `json:"cniVersion"`
	Name       string `json:"name"`
	Type       string `json:"type"`
}

// IPConfig represents an IP configuration in the CNI result.
type IPConfig struct {
	Address string `json:"address"`
	Gateway string `json:"gateway,omitempty"`
}

// RouteConfig represents a route in the CNI result.
type RouteConfig struct {
	Dst string `json:"dst"`
	GW  string `json:"gw,omitempty"`
}

// DNSResult represents DNS configuration in the CNI result.
type DNSResult struct {
	Nameservers []string `json:"nameservers,omitempty"`
	Domain      string   `json:"domain,omitempty"`
	Search      []string `json:"search,omitempty"`
}

// CNIResult represents the standard CNI success result.
type CNIResult struct {
	CNIVersion string        `json:"cniVersion"`
	IPs        []IPConfig    `json:"ips"`
	Routes     []RouteConfig `json:"routes,omitempty"`
	DNS        DNSResult     `json:"dns,omitempty"`
}

// CNIError represents the standard CNI error result.
type CNIError struct {
	Code    uint   `json:"code"`
	Msg     string `json:"msg"`
	Details string `json:"details,omitempty"`
}

func main() {
	// 1. Read CNI config from stdin
	configData, err := io.ReadAll(os.Stdin)
	if err != nil {
		outputError(1, "failed to read CNI config from stdin", err.Error())
		return
	}

	var config CNIConfig
	if err := json.Unmarshal(configData, &config); err != nil {
		outputError(2, "failed to parse CNI config JSON", err.Error())
		return
	}

	// 2. Read environment variables
	command := os.Getenv("CNI_COMMAND")
	containerID := os.Getenv("CNI_CONTAINERID")
	netns := os.Getenv("CNI_NETNS")
	ifName := os.Getenv("CNI_IFNAME")
	argsStr := os.Getenv("CNI_ARGS")

	if command == "VERSION" {
		outputVersion()
		return
	}

	if command == "" {
		outputError(3, "CNI_COMMAND is not set", "")
		return
	}

	// 3. Parse CNI_ARGS
	k8sArgs := parseCNIArgs(argsStr)
	podName := k8sArgs["K8S_POD_NAME"]
	podNamespace := k8sArgs["K8S_POD_NAMESPACE"]

	// 4. Initialize gRPC client
	client := grpc.NewClient(grpc.SocketPath)

	// 5. Handle command
	switch command {
	case "ADD":
		req := &grpc.AddRequest{
			ContainerID:  containerID,
			Netns:        netns,
			IfName:       ifName,
			PodName:      podName,
			PodNamespace: podNamespace,
			Args:         k8sArgs,
		}
		resp, err := client.Add(req)
		if err != nil {
			outputError(4, "failed to call node agent ADD", err.Error())
			return
		}
		if resp.Error != "" {
			outputError(5, "node agent returned error for ADD", resp.Error)
			return
		}

		result := &CNIResult{
			CNIVersion: config.CNIVersion,
			IPs: []IPConfig{
				{
					Address: resp.IP,
					Gateway: resp.Gateway,
				},
			},
			DNS: DNSResult{
				Nameservers: resp.DNS.Nameservers,
				Domain:      resp.DNS.Domain,
				Search:      resp.DNS.Search,
			},
		}
		for _, r := range resp.Routes {
			result.Routes = append(result.Routes, RouteConfig{
				Dst: r.Dst,
				GW:  r.GW,
			})
		}
		outputResult(result)

	case "DEL":
		req := &grpc.DelRequest{
			ContainerID:  containerID,
			Netns:        netns,
			IfName:       ifName,
			PodName:      podName,
			PodNamespace: podNamespace,
		}
		resp, err := client.Del(req)
		if err != nil {
			outputError(4, "failed to call node agent DEL", err.Error())
			return
		}
		if resp.Error != "" {
			outputError(5, "node agent returned error for DEL", resp.Error)
			return
		}
		outputResult(nil) // Empty response for DEL

	case "CHECK":
		req := &grpc.CheckRequest{
			ContainerID:  containerID,
			Netns:        netns,
			IfName:       ifName,
			PodName:      podName,
			PodNamespace: podNamespace,
		}
		resp, err := client.Check(req)
		if err != nil {
			outputError(4, "failed to call node agent CHECK", err.Error())
			return
		}
		if resp.Error != "" || !resp.OK {
			msg := resp.Error
			if msg == "" {
				msg = "check failed"
			}
			outputError(5, "node agent returned error for CHECK", msg)
			return
		}
		outputResult(nil)

	default:
		outputError(3, "unsupported CNI_COMMAND", command)
	}
}

func parseCNIArgs(argsStr string) map[string]string {
	args := make(map[string]string)
	if argsStr == "" {
		return args
	}

	pairs := strings.Split(argsStr, ";")
	for _, pair := range pairs {
		kv := strings.Split(pair, "=")
		if len(kv) == 2 {
			args[kv[0]] = kv[1]
		}
	}
	return args
}

func outputResult(result interface{}) {
	if result == nil {
		return
	}
	data, _ := json.Marshal(result)
	os.Stdout.Write(data)
}

func outputError(code uint, msg string, details string) {
	cniErr := CNIError{
		Code:    code,
		Msg:     msg,
		Details: details,
	}
	data, _ := json.Marshal(cniErr)
	os.Stdout.Write(data)
	os.Exit(1)
}

func outputVersion() {
	versionInfo := map[string]interface{}{
		"cniVersion":        "1.0.0",
		"supportedVersions": []string{"0.3.0", "0.3.1", "0.4.0", "1.0.0"},
	}
	data, _ := json.Marshal(versionInfo)
	os.Stdout.Write(data)
}

package policy

// PlatformRules generates the platform-mandated allow rules.
type PlatformRules struct {
	dnsServers      []string
	monitoringCIDRs []string
	monitoringPort  int
}

// NewPlatformRules creates a new PlatformRules with default monitoring port.
func NewPlatformRules() *PlatformRules {
	return &PlatformRules{
		monitoringPort: 9090,
	}
}

// SetDNSServers sets the DNS server IPs.
func (p *PlatformRules) SetDNSServers(servers []string) {
	p.dnsServers = servers
}

// SetMonitoringCIDRs sets the monitoring CIDR ranges.
func (p *PlatformRules) SetMonitoringCIDRs(cidrs []string) {
	p.monitoringCIDRs = cidrs
}

// SetMonitoringPort sets the monitoring scrape port.
func (p *PlatformRules) SetMonitoringPort(port int) {
	p.monitoringPort = port
}

// GenerateRules returns the platform-mandated allow rules.
func (p *PlatformRules) GenerateRules() []PolicyRule {
	var rules []PolicyRule

	// DNS allow rules: allow all identities to reach DNS servers on UDP/TCP port 53
	rules = append(rules, PolicyRule{
		SrcIdentity: 0, // Wildcard source
		DstIdentity: 0, // Wildcard destination (representing DNS servers)
		Proto:       "UDP",
		Port:        53,
		Verdict:     VerdictAllow,
		PolicyName:  "platform-dns-udp",
		Tier:        TierPlatformMandated,
	})
	rules = append(rules, PolicyRule{
		SrcIdentity: 0,
		DstIdentity: 0,
		Proto:       "TCP",
		Port:        53,
		Verdict:     VerdictAllow,
		PolicyName:  "platform-dns-tcp",
		Tier:        TierPlatformMandated,
	})

	// Monitoring scrape allow rules: allow monitoring CIDRs to reach all identities on the monitoring port
	rules = append(rules, PolicyRule{
		SrcIdentity: 0, // Wildcard source (representing monitoring CIDRs)
		DstIdentity: 0, // Wildcard destination (representing all target pods)
		Proto:       "TCP",
		Port:        p.monitoringPort,
		Verdict:     VerdictAllow,
		PolicyName:  "platform-monitoring",
		Tier:        TierPlatformMandated,
	})

	return rules
}

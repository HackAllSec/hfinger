package models

import (
	"net"
	"sort"
	"strings"

	"hfinger/rules"
)

var knownEdgeCIDRs = []struct {
	name string
	cidr string
}{
	{name: "Cloudflare", cidr: "173.245.48.0/20"},
	{name: "Cloudflare", cidr: "103.21.244.0/22"},
	{name: "Cloudflare", cidr: "103.22.200.0/22"},
	{name: "Cloudflare", cidr: "103.31.4.0/22"},
	{name: "Cloudflare", cidr: "141.101.64.0/18"},
	{name: "Cloudflare", cidr: "108.162.192.0/18"},
	{name: "Cloudflare", cidr: "190.93.240.0/20"},
	{name: "Cloudflare", cidr: "188.114.96.0/20"},
	{name: "Cloudflare", cidr: "197.234.240.0/22"},
	{name: "Cloudflare", cidr: "198.41.128.0/17"},
	{name: "Cloudflare", cidr: "162.158.0.0/15"},
	{name: "Cloudflare", cidr: "104.16.0.0/13"},
	{name: "Cloudflare", cidr: "104.24.0.0/14"},
	{name: "Cloudflare", cidr: "172.64.0.0/13"},
	{name: "Cloudflare", cidr: "131.0.72.0/22"},
	{name: "Cloudflare", cidr: "2400:cb00::/32"},
	{name: "Cloudflare", cidr: "2606:4700::/32"},
	{name: "Cloudflare", cidr: "2803:f800::/32"},
	{name: "Cloudflare", cidr: "2405:b500::/32"},
	{name: "Cloudflare", cidr: "2405:8100::/32"},
	{name: "Cloudflare", cidr: "2a06:98c0::/29"},
	{name: "Cloudflare", cidr: "2c0f:f248::/32"},
	{name: "Fastly", cidr: "151.101.0.0/16"},
	{name: "Fastly", cidr: "199.232.0.0/16"},
	{name: "Akamai", cidr: "23.32.0.0/11"},
	{name: "Akamai", cidr: "23.64.0.0/14"},
	{name: "Akamai", cidr: "23.72.0.0/13"},
	{name: "Akamai", cidr: "104.64.0.0/10"},
	{name: "Amazon CloudFront", cidr: "13.32.0.0/15"},
	{name: "Amazon CloudFront", cidr: "13.224.0.0/14"},
	{name: "Amazon CloudFront", cidr: "52.84.0.0/15"},
	{name: "Amazon CloudFront", cidr: "54.230.0.0/16"},
	{name: "Azure Front Door", cidr: "13.107.246.0/24"},
	{name: "Azure Front Door", cidr: "13.107.213.0/24"},
}

var parsedEdgeCIDRs = parseEdgeCIDRs()

func parseEdgeCIDRs() []struct {
	name string
	net  *net.IPNet
} {
	items := make([]struct {
		name string
		net  *net.IPNet
	}, 0, len(knownEdgeCIDRs))
	for _, item := range knownEdgeCIDRs {
		_, network, err := net.ParseCIDR(item.cidr)
		if err != nil {
			continue
		}
		items = append(items, struct {
			name string
			net  *net.IPNet
		}{name: item.name, net: network})
	}
	return items
}

func enrichEdgeNetworks(info *rules.DNSInfo) {
	if info == nil || len(info.IPs) == 0 {
		return
	}
	seen := map[string]struct{}{}
	for _, raw := range info.IPs {
		ip := net.ParseIP(strings.TrimSpace(raw))
		if ip == nil {
			continue
		}
		for _, item := range parsedEdgeCIDRs {
			if item.net.Contains(ip) {
				seen[item.name] = struct{}{}
			}
		}
	}
	for name := range seen {
		info.EdgeNetworks = append(info.EdgeNetworks, name)
	}
	sort.Strings(info.EdgeNetworks)
}

package rules

import "strings"

func ActiveHTTPProbes() []Probe {
	seen := make(map[string]struct{})
	var probes []Probe
	for _, rule := range ActiveRules() {
		for _, probe := range normalizedProbes(rule) {
			path := strings.TrimSpace(probe.Request.Path)
			if path == "" || path == "/" {
				continue
			}
			key := probe.ID + "\x00" + path
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			probes = append(probes, probe)
		}
	}
	return probes
}

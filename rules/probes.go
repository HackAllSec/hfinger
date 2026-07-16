package rules

import "strings"

func ActiveHTTPProbes() []Probe {
	if activeHTTPProbePlan != nil {
		return append([]Probe{}, activeHTTPProbePlan...)
	}
	_ = ActiveRules()
	return append([]Probe{}, activeHTTPProbePlan...)
}

func buildHTTPProbePlan(ruleSet []Rule) []Probe {
	seen := make(map[string]struct{})
	var probes []Probe
	for _, rule := range ruleSet {
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

package rules

import "strings"

func ActiveHTTPProbes() []Probe {
	if activeHTTPProbePlan != nil {
		return cloneProbes(activeHTTPProbePlan)
	}
	_ = ActiveRules()
	return cloneProbes(activeHTTPProbePlan)
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
			probes = append(probes, cloneProbe(probe))
		}
	}
	return probes
}

func cloneProbes(probes []Probe) []Probe {
	cloned := make([]Probe, 0, len(probes))
	for _, probe := range probes {
		cloned = append(cloned, cloneProbe(probe))
	}
	return cloned
}

func cloneProbe(probe Probe) Probe {
	probe.Request.Headers = cloneStringMap(probe.Request.Headers)
	probe.Request.AllowStatus = append([]int{}, probe.Request.AllowStatus...)
	probe.Matchers = cloneMatchers(probe.Matchers)
	return probe
}

func cloneMatchers(matchers []Matcher) []Matcher {
	cloned := make([]Matcher, 0, len(matchers))
	for _, matcher := range matchers {
		matcher.Values = append([]string{}, matcher.Values...)
		cloned = append(cloned, matcher)
	}
	return cloned
}

func cloneStringMap(values map[string]string) map[string]string {
	if values == nil {
		return nil
	}
	cloned := make(map[string]string, len(values))
	for key, value := range values {
		cloned[key] = value
	}
	return cloned
}

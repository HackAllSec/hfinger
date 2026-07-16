package rules

import (
	"sort"
	"strings"
)

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
			key := probePlanKey(probe)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			probes = append(probes, cloneProbe(probe))
		}
	}
	return probes
}

func probePlanKey(probe Probe) string {
	// 主动探测请求不只由路径决定；method/body/header 不同会产生不同服务端行为。
	// 去重键必须包含完整请求语义，避免把 API 探测和普通路径探测合并掉。
	var builder strings.Builder
	builder.WriteString(probe.ID)
	builder.WriteString("\x00")
	builder.WriteString(strings.ToUpper(strings.TrimSpace(probe.Request.Method)))
	builder.WriteString("\x00")
	builder.WriteString(strings.TrimSpace(probe.Request.Path))
	builder.WriteString("\x00")
	builder.WriteString(probe.Request.Body)
	keys := make([]string, 0, len(probe.Request.Headers))
	for key := range probe.Request.Headers {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		builder.WriteString("\x00")
		builder.WriteString(strings.ToLower(key))
		builder.WriteString("=")
		builder.WriteString(probe.Request.Headers[key])
	}
	return builder.String()
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

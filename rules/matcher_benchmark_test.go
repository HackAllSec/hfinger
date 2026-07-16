package rules

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
)

func BenchmarkMatchRulesCompiledContains(b *testing.B) {
	ruleSet := benchmarkRuleSet(200, "body.contains")
	responses := []Response{benchmarkResponse()}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		results := MatchRules(responses, ruleSet)
		if len(results) == 0 {
			b.Fatal("expected at least one match")
		}
	}
}

func BenchmarkMatchCompiledRuntimeContains(b *testing.B) {
	compiled := compileRules(benchmarkRuleSet(200, "body.contains"))
	responses := []Response{benchmarkResponse()}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		results := matchCompiledRules(responses, compiled)
		if len(results) == 0 {
			b.Fatal("expected at least one match")
		}
	}
}

func BenchmarkMatchRulesCompiledRegex(b *testing.B) {
	ruleSet := benchmarkRuleSet(100, "body.regex")
	responses := []Response{benchmarkResponse()}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		results := MatchRules(responses, ruleSet)
		if len(results) == 0 {
			b.Fatal("expected at least one match")
		}
	}
}

func BenchmarkMatchCompiledRuntimeRegex(b *testing.B) {
	compiled := compileRules(benchmarkRuleSet(100, "body.regex"))
	responses := []Response{benchmarkResponse()}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		results := matchCompiledRules(responses, compiled)
		if len(results) == 0 {
			b.Fatal("expected at least one match")
		}
	}
}

func BenchmarkMatchRulesCompiledJSON(b *testing.B) {
	ruleSet := benchmarkJSONRuleSet(100)
	responses := []Response{benchmarkJSONResponse()}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		results := MatchRules(responses, ruleSet)
		if len(results) == 0 {
			b.Fatal("expected at least one match")
		}
	}
}

func BenchmarkMatchCompiledRuntimeJSON(b *testing.B) {
	compiled := compileRules(benchmarkJSONRuleSet(100))
	responses := []Response{benchmarkJSONResponse()}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		results := matchCompiledRules(responses, compiled)
		if len(results) == 0 {
			b.Fatal("expected at least one match")
		}
	}
}

func BenchmarkMatchCompiledRuntimeProbes(b *testing.B) {
	compiled := compileRules(benchmarkProbeRuleSet(100, 8))
	responses := benchmarkProbeResponses(8)

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		results := matchCompiledRules(responses, compiled)
		if len(results) == 0 {
			b.Fatal("expected at least one match")
		}
	}
}

func benchmarkJSONRuleSet(count int) []Rule {
	ruleSet := make([]Rule, count)
	for i := range ruleSet {
		ruleSet[i] = Rule{
			ID:       fmt.Sprintf("bench-json-%03d", i),
			Name:     fmt.Sprintf("Bench JSON %03d", i),
			Category: "benchmark",
			Match: MatchBlock{
				Strategy: StrategyAny,
				Matchers: []Matcher{
					{Type: "json.key.exists", Value: "request_id"},
					{Type: "json.path.eq", Key: "error.code", Value: "UNAUTHORIZED"},
				},
			},
		}
	}
	return ruleSet
}

func benchmarkJSONResponse() Response {
	return Response{
		URL:  "https://example.com/api",
		Body: []byte(`{"error":{"code":"UNAUTHORIZED"},"request_id":"abc","data":{"items":[1,2,3]}}`),
	}
}

func benchmarkProbeRuleSet(ruleCount int, probeCount int) []Rule {
	ruleSet := make([]Rule, ruleCount)
	for i := range ruleSet {
		probes := make([]Probe, 0, probeCount)
		for probeIndex := 0; probeIndex < probeCount; probeIndex++ {
			probes = append(probes, Probe{
				ID: fmt.Sprintf("probe-%02d", probeIndex),
				Request: Request{
					Path: fmt.Sprintf("/probe-%02d", probeIndex),
				},
				Matchers: []Matcher{{
					Type:  "body.contains",
					Value: fmt.Sprintf("probe-%02d-signal-%03d", probeIndex, i),
				}},
			})
		}
		ruleSet[i] = Rule{
			ID:       fmt.Sprintf("bench-probes-%03d", i),
			Name:     fmt.Sprintf("Bench Probes %03d", i),
			Category: "benchmark",
			Match: MatchBlock{
				Strategy: StrategyAny,
				Probes:   probes,
			},
		}
	}
	return ruleSet
}

func benchmarkProbeResponses(count int) []Response {
	responses := make([]Response, 0, count)
	for i := 0; i < count; i++ {
		responses = append(responses, Response{
			ProbeID: fmt.Sprintf("probe-%02d", i),
			URL:     fmt.Sprintf("https://example.com/probe-%02d", i),
			Path:    fmt.Sprintf("/probe-%02d", i),
			Body:    []byte(fmt.Sprintf("probe-%02d-signal-000", i)),
		})
	}
	return responses
}

func benchmarkRuleSet(count int, matcherType string) []Rule {
	ruleSet := make([]Rule, count)
	for i := range ruleSet {
		value := fmt.Sprintf("bench-signal-%03d", i)
		if matcherType == "body.regex" {
			value = fmt.Sprintf(`bench-signal-%03d`, i)
		}
		ruleSet[i] = Rule{
			ID:       fmt.Sprintf("bench-%s-%03d", strings.ReplaceAll(matcherType, ".", "-"), i),
			Name:     fmt.Sprintf("Bench %03d", i),
			Category: "benchmark",
			Match: MatchBlock{
				Strategy: StrategyAny,
				Matchers: []Matcher{
					{Type: matcherType, Value: value},
				},
			},
		}
	}
	return ruleSet
}

func benchmarkResponse() Response {
	var body strings.Builder
	for i := 0; i < 200; i++ {
		body.WriteString(fmt.Sprintf("content block %03d bench-signal-%03d\n", i, i))
	}
	return Response{
		URL:        "https://example.com/",
		StatusCode: 200,
		Title:      "Benchmark",
		Header: http.Header{
			"Server":       {"nginx"},
			"X-Powered-By": {"benchmark"},
		},
		Body: []byte(body.String()),
	}
}

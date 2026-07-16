package rules

import (
	"net/http"
	"strings"
	"testing"
)

func TestMatchRuleScoreAndEvidence(t *testing.T) {
	response := Response{
		URL:        "https://example.com/",
		Path:       "/",
		StatusCode: 200,
		Title:      "Admin Portal",
		Header: http.Header{
			"Server": {"nginx"},
		},
		Body: []byte(`<html><script src="/static/app.js"></script></html>`),
	}

	rule := Rule{
		ID:       "example",
		Name:     "Example",
		Category: "web",
		Match: MatchBlock{
			Strategy:  StrategyScore,
			Threshold: 70,
			Probes: []Probe{{
				ID: "homepage",
				Matchers: []Matcher{
					{Type: "header.contains", Key: "Server", Value: "nginx", Weight: 40},
					{Type: "script.src.contains", Value: "/static/app.js", Weight: 40},
				},
			}},
		},
	}

	result := MatchRule([]Response{response}, rule)
	if !result.Matched {
		t.Fatalf("MatchRule() expected match")
	}
	if result.Confidence != 100 {
		t.Fatalf("confidence = %d, want 100", result.Confidence)
	}
	if len(result.Evidence) != 2 {
		t.Fatalf("evidence length = %d, want 2", len(result.Evidence))
	}
}

func TestMatchRuleNegativeExcludes(t *testing.T) {
	response := Response{
		URL:    "https://example.com/",
		Path:   "/",
		Header: http.Header{"Server": {"openresty"}},
		Body:   []byte("welcome to nginx"),
	}
	rule := Rule{
		ID:       "nginx",
		Name:     "Nginx",
		Category: "reverse-proxy",
		Match: MatchBlock{
			Strategy: StrategyAny,
			Matchers: []Matcher{
				{Type: "body.contains", Value: "nginx"},
			},
		},
		Negative: []Matcher{
			{Type: "header.contains", Key: "Server", Value: "openresty"},
		},
	}

	result := MatchRule([]Response{response}, rule)
	if result.Matched {
		t.Fatalf("MatchRule() expected negative rule to exclude match")
	}
	if !result.Excluded {
		t.Fatalf("MatchRule() expected excluded=true")
	}
}

func TestMatchRuleContainsAutomatonKeepsMatcherValueOrder(t *testing.T) {
	response := Response{
		URL:  "https://example.com/",
		Body: []byte("second signal appears before first signal"),
	}
	rule := Rule{
		ID:       "contains-order",
		Name:     "Contains Order",
		Category: "test",
		Match: MatchBlock{
			Matchers: []Matcher{{
				Type:   "body.contains",
				Values: []string{"first signal", "second signal"},
			}},
		},
	}

	result := MatchRule([]Response{response}, rule)
	if !result.Matched {
		t.Fatalf("MatchRule() expected match")
	}
	if len(result.Evidence) != 1 {
		t.Fatalf("evidence length = %d, want 1", len(result.Evidence))
	}
	if got := result.Evidence[0].MatchedValue; !strings.Contains(got, "first signal") {
		t.Fatalf("MatchedValue = %q, want first signal evidence", got)
	}
}

func TestMatchRuleContainsAutomatonKeepsEmptyValueSemantics(t *testing.T) {
	body := strings.Repeat("prefix ", 40) + "second signal"
	response := Response{
		URL:  "https://example.com/",
		Body: []byte(body),
	}
	rule := Rule{
		ID:       "contains-empty-value",
		Name:     "Contains Empty Value",
		Category: "test",
		Match: MatchBlock{
			Matchers: []Matcher{{
				Type:   "body.contains",
				Values: []string{"", "second signal"},
			}},
		},
	}

	result := MatchRule([]Response{response}, rule)
	if !result.Matched {
		t.Fatalf("MatchRule() expected match")
	}
	if len(result.Evidence) != 1 {
		t.Fatalf("evidence length = %d, want 1", len(result.Evidence))
	}
	if got := result.Evidence[0].MatchedValue; strings.Contains(got, "second signal") {
		t.Fatalf("MatchedValue = %q, want empty value to keep first-match semantics", got)
	}
}

func TestMatchRuleAnyConfidenceUsesMatchedWeight(t *testing.T) {
	response := Response{
		URL:  "https://example.com/",
		Body: []byte("strong-signal"),
	}
	rule := Rule{
		ID:       "any-confidence",
		Name:     "Any Confidence",
		Category: "web",
		Match: MatchBlock{
			Strategy: StrategyAny,
			Matchers: []Matcher{
				{Type: "body.contains", Value: "strong-signal", Weight: 40},
				{Type: "body.contains", Value: "missing-signal", Weight: 60},
			},
		},
	}

	result := MatchRule([]Response{response}, rule)
	if !result.Matched {
		t.Fatalf("MatchRule() expected match")
	}
	if result.Confidence != 40 {
		t.Fatalf("confidence = %d, want 40", result.Confidence)
	}
}

func TestMatchRuleAnyConfidenceIncludesMissingProbeWeight(t *testing.T) {
	response := Response{
		ProbeID: "homepage",
		URL:     "https://example.com/",
		Path:    "/",
		Body:    []byte("homepage-signal"),
	}
	rule := Rule{
		ID:       "any-confidence-probes",
		Name:     "Any Confidence Probes",
		Category: "web",
		Match: MatchBlock{
			Strategy: StrategyAny,
			Probes: []Probe{
				{
					ID: "homepage",
					Request: Request{
						Path: "/",
					},
					Matchers: []Matcher{
						{Type: "body.contains", Value: "homepage-signal", Weight: 40},
					},
				},
				{
					ID: "missing-admin",
					Request: Request{
						Path: "/admin",
					},
					Matchers: []Matcher{
						{Type: "body.contains", Value: "admin-signal", Weight: 60},
					},
				},
			},
		},
	}

	result := MatchRule([]Response{response}, rule)
	if !result.Matched {
		t.Fatalf("MatchRule() expected match")
	}
	if result.Confidence != 40 {
		t.Fatalf("confidence = %d, want 40", result.Confidence)
	}
}

func TestMatchRuleUsesPreparedResponseProbeIndex(t *testing.T) {
	responses := []Response{
		{
			ProbeID: "homepage",
			URL:     "https://example.com/",
			Path:    "/",
			Body:    []byte("home signal"),
		},
		{
			URL:  "https://example.com/admin",
			Path: "/admin",
			Body: []byte("admin signal"),
		},
		{
			ProbeID: "admin",
			URL:     "https://example.com/admin-by-id",
			Path:    "/other-admin-path",
			Body:    []byte("admin-id signal"),
		},
	}
	rule := Rule{
		ID:       "multi-probe-index",
		Name:     "Multi Probe Index",
		Category: "test",
		Match: MatchBlock{
			Strategy: StrategyAll,
			Probes: []Probe{
				{
					ID: "homepage",
					Request: Request{
						Path: "/",
					},
					Matchers: []Matcher{
						{Type: "body.contains", Value: "home signal", Weight: 50},
					},
				},
				{
					ID: "admin",
					Request: Request{
						Path: "/admin",
					},
					Matchers: []Matcher{
						{Type: "body.contains", Value: "admin signal", Weight: 50},
					},
				},
				{
					ID: "admin",
					Request: Request{
						Path: "/other-admin-path",
					},
					Matchers: []Matcher{
						{Type: "body.contains", Value: "admin-id signal", Weight: 50},
					},
				},
			},
		},
	}

	result := MatchRule(responses, rule)
	if !result.Matched {
		t.Fatalf("MatchRule() expected match through probe/path indexes")
	}
	if len(result.Evidence) != 3 {
		t.Fatalf("evidence length = %d, want 3", len(result.Evidence))
	}
}

func TestMatchRuleExtractsVersion(t *testing.T) {
	response := Response{
		URL: "https://jenkins.example",
		Header: map[string][]string{
			"X-Jenkins": {"2.440.1"},
		},
	}
	rule := Rule{
		ID:       "jenkins-version",
		Name:     "Jenkins",
		Category: "devops",
		Match: MatchBlock{Matchers: []Matcher{
			{Type: "header.contains", Key: "X-Jenkins", Weight: 100},
		}},
		Extract: []Extractor{{
			Name:  "version",
			Type:  "header",
			Key:   "X-Jenkins",
			Regex: `([0-9]+(?:\.[0-9]+)+)`,
			Group: 1,
		}},
	}

	result := MatchRule([]Response{response}, rule)
	if !result.Matched {
		t.Fatalf("MatchRule() expected match")
	}
	if result.Version != "2.440.1" {
		t.Fatalf("Version = %q, want 2.440.1", result.Version)
	}
}

func TestMatchResponseStatusAndRegex(t *testing.T) {
	response := Response{
		URL:        "https://example.com/login",
		Path:       "/login",
		StatusCode: 401,
		Body:       []byte(`{"code":"UNAUTHORIZED"}`),
	}

	if _, ok := MatchResponse(response, Matcher{Type: "status.in", Value: []interface{}{401, 403}}); !ok {
		t.Fatalf("status.in expected match")
	}
	if _, ok := MatchResponse(response, Matcher{Type: "body.regex", Value: `"code":"[A-Z_]+"`}); !ok {
		t.Fatalf("body.regex expected match")
	}
}

func TestMatchResponseJSONAndTLS(t *testing.T) {
	response := Response{
		URL:        "https://api.example.com",
		StatusCode: 401,
		Body:       []byte(`{"error":{"code":"UNAUTHORIZED"},"request_id":"abc"}`),
		TLS: TLSInfo{
			Subject:  "CN=api.example.com",
			Issuer:   "CN=Example CA",
			DNSNames: []string{"api.example.com"},
			ALPN:     "h2",
		},
	}

	if _, ok := MatchResponse(response, Matcher{Type: "json.key.exists", Value: "request_id"}); !ok {
		t.Fatalf("json.key.exists expected match")
	}
	if _, ok := MatchResponse(response, Matcher{Type: "json.path.eq", Key: "error.code", Value: "UNAUTHORIZED"}); !ok {
		t.Fatalf("json.path.eq expected match")
	}
	if _, ok := MatchResponse(response, Matcher{Type: "tls.cert.issuer.contains", Value: "Example CA"}); !ok {
		t.Fatalf("tls.cert.issuer.contains expected match")
	}
	if _, ok := MatchResponse(response, Matcher{Type: "tls.alpn.contains", Value: "h2"}); !ok {
		t.Fatalf("tls.alpn.contains expected match")
	}
}

func TestMatchResponseHeaderIndexPreservesSemantics(t *testing.T) {
	response := Response{
		URL: "https://example.com/",
		Header: http.Header{
			"Server":          {"nginx"},
			"X-Empty-Header":  {},
			"X-Powered-By":    {"PHP/8.2"},
			"X-Custom-Header": {"Alpha Beta"},
		},
	}

	tests := []Matcher{
		{Type: "header.contains", Key: "server", Value: "nginx"},
		{Type: "header.contains", Key: "X-Empty-Header"},
		{Type: "header.contains", Value: "X-Powered-By"},
		{Type: "header.regex", Key: "x-custom-header", Value: `Alpha\s+Beta`},
	}
	for _, matcher := range tests {
		if _, ok := MatchResponse(response, matcher); !ok {
			t.Fatalf("%s key=%q value=%v expected match", matcher.Type, matcher.Key, matcher.Value)
		}
	}
}

func TestCompiledRulesForCachesByRuleContent(t *testing.T) {
	ruleSet := []Rule{{
		ID:       "cache-test",
		Name:     "Cache Test",
		Category: "test",
		Match: MatchBlock{Matchers: []Matcher{
			{Type: "body.contains", Value: "cache-signal"},
		}},
	}}
	sameContent := append([]Rule{}, ruleSet...)

	first := compiledRulesFor(ruleSet)
	second := compiledRulesFor(sameContent)
	if len(first) == 0 || len(second) == 0 {
		t.Fatalf("compiledRulesFor() returned empty result")
	}
	if &first[0] != &second[0] {
		t.Fatalf("compiledRulesFor() did not reuse cache for equivalent rules")
	}

	sameContent[0].Match.Matchers[0].Value = "changed-signal"
	changed := compiledRulesFor(sameContent)
	if got := changed[0].probes[0].matchers[0].values[0]; got != "changed-signal" {
		t.Fatalf("compiledRulesFor() returned stale cache, matcher value = %q", got)
	}
}

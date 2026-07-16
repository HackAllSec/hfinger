package rules

import (
	"net/http"
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

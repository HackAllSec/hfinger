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

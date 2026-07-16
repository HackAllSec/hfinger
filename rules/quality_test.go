package rules

import "testing"

func TestLintRulesReportsWeakRules(t *testing.T) {
	report := LintRules([]Rule{{
		ID:       "weak",
		Name:     "Weak",
		Category: "web",
		Match: MatchBlock{Matchers: []Matcher{
			{Type: "body.contains", Value: "OK"},
		}},
	}})

	if report.HasErrors() {
		t.Fatalf("LintRules() unexpected errors: %#v", report.Errors)
	}
	if len(report.Warnings) == 0 {
		t.Fatalf("LintRules() expected warnings")
	}
}

func TestTestRulesFixtures(t *testing.T) {
	rule := Rule{
		ID:       "fixture-rule",
		Name:     "Fixture Rule",
		Category: "web",
		Match: MatchBlock{
			Strategy: StrategyAny,
			Matchers: []Matcher{
				{Type: "body.contains", Value: "Unique Product"},
			},
		},
		Examples: Examples{
			Positive: []Fixture{{Name: "positive", Body: "Welcome Unique Product"}},
			Negative: []Fixture{{Name: "negative", Body: "Other Product"}},
		},
	}

	if failures := TestRules([]Rule{rule}); len(failures) != 0 {
		t.Fatalf("TestRules() failures = %#v", failures)
	}
}

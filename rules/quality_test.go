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

func TestStatsReportsRuleTiers(t *testing.T) {
	report := Stats([]Rule{
		{ID: "core-0001-example", Name: "Curated", Category: "devops"},
		{ID: "builtin-0001-example", Name: "Migrated", Category: "cms"},
		{ID: "custom-example", Name: "External", Category: "internal"},
	})

	if report.Tiers["curated"] != 1 {
		t.Fatalf("curated tier = %d, want 1", report.Tiers["curated"])
	}
	if report.Tiers["migrated"] != 1 {
		t.Fatalf("migrated tier = %d, want 1", report.Tiers["migrated"])
	}
	if report.Tiers["external"] != 1 {
		t.Fatalf("external tier = %d, want 1", report.Tiers["external"])
	}
}

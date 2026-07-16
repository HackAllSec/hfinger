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
		statsCleanRule("core-0001-example", "Curated", "devops"),
		statsCleanRule("builtin-0001-example", "Migrated", "cms"),
		statsCleanRule("custom-example", "External", "internal"),
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
	if report.LintErrors != 0 {
		t.Fatalf("LintErrors = %d, want 0", report.LintErrors)
	}
	if report.LintWarnings != 0 {
		t.Fatalf("LintWarnings = %d, want 0", report.LintWarnings)
	}
}

func TestStatsReportsLintIssuesByTier(t *testing.T) {
	report := Stats([]Rule{
		{
			ID:       "builtin-0001-weak",
			Name:     "Weak Migrated",
			Category: "cms",
			Match: MatchBlock{Matchers: []Matcher{
				{Type: "body.contains", Value: "OK"},
			}},
		},
		{
			ID:       "custom-invalid",
			Name:     "Invalid External",
			Category: "internal",
			Metadata: Metadata{References: []string{"https://example.com"}},
			Negative: []Matcher{{Type: "body.contains", Value: "documentation"}},
			Match: MatchBlock{Matchers: []Matcher{
				{Type: "unsupported.matcher", Value: "invalid-signal"},
				{Type: "header.contains", Value: "stable-signal"},
			}},
		},
	})

	if report.LintWarnings == 0 {
		t.Fatalf("LintWarnings = 0, want migrated warning count")
	}
	if report.LintWarningsByTier["migrated"] != report.LintWarnings {
		t.Fatalf("migrated warnings = %d, want %d", report.LintWarningsByTier["migrated"], report.LintWarnings)
	}
	if report.LintErrors != 1 {
		t.Fatalf("LintErrors = %d, want 1", report.LintErrors)
	}
	if report.LintErrorsByTier["external"] != 1 {
		t.Fatalf("external errors = %d, want 1", report.LintErrorsByTier["external"])
	}
}

func TestDoctorReportsTopIssuesAndSuggestions(t *testing.T) {
	report := Doctor([]Rule{
		{
			ID:       "builtin-0001-weak",
			Name:     "Weak Migrated",
			Category: "cms",
			Match: MatchBlock{Matchers: []Matcher{
				{Type: "body.contains", Value: "OK"},
			}},
		},
		{
			ID:       "builtin-0002-weak",
			Name:     "Another Weak Migrated",
			Category: "cms",
			Match: MatchBlock{Matchers: []Matcher{
				{Type: "body.contains", Value: "NO"},
			}},
		},
		statsCleanRule("core-0001-clean", "Clean", "devops"),
	}, 1)

	if report.Stats.LintWarnings == 0 {
		t.Fatalf("LintWarnings = 0, want warnings")
	}
	if len(report.Issues) == 0 {
		t.Fatalf("Doctor() issues empty")
	}
	if len(report.Rules) != 1 {
		t.Fatalf("Doctor() rules length = %d, want 1", len(report.Rules))
	}
	if !report.HasMore {
		t.Fatalf("Doctor() HasMore = false, want true")
	}
	rule := report.Rules[0]
	if rule.RuleID != "builtin-0001-weak" {
		t.Fatalf("Doctor() top rule = %s, want builtin-0001-weak", rule.RuleID)
	}
	if len(rule.Suggestions) == 0 {
		t.Fatalf("Doctor() suggestions empty")
	}
}

func TestDoctorCanReturnSummaryOnly(t *testing.T) {
	report := Doctor([]Rule{
		{
			ID:       "builtin-0001-weak",
			Name:     "Weak Migrated",
			Category: "cms",
			Match: MatchBlock{Matchers: []Matcher{
				{Type: "body.contains", Value: "OK"},
			}},
		},
	}, 0)

	if len(report.Rules) != 0 {
		t.Fatalf("Doctor() rules length = %d, want 0", len(report.Rules))
	}
	if !report.HasMore {
		t.Fatalf("Doctor() HasMore = false, want true")
	}
}

func statsCleanRule(id string, name string, category string) Rule {
	return Rule{
		ID:       id,
		Name:     name,
		Category: category,
		Metadata: Metadata{References: []string{"https://example.com"}},
		Negative: []Matcher{{Type: "body.contains", Value: "documentation"}},
		Match: MatchBlock{Matchers: []Matcher{
			{Type: "header.contains", Value: "stable-signal"},
		}},
	}
}

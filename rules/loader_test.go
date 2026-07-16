package rules

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadYAMLFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "example.yaml")
	content := []byte(`
id: example-app
name: Example App
category: web
match:
  strategy: any
  matchers:
    - type: body.contains
      value: Example
metadata:
  references:
    - https://example.com
`)
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	loaded, err := LoadYAMLFile(path)
	if err != nil {
		t.Fatalf("LoadYAMLFile() error: %v", err)
	}
	if len(loaded) != 1 {
		t.Fatalf("loaded length = %d, want 1", len(loaded))
	}
	if loaded[0].ID != "example-app" || loaded[0].Match.Strategy != StrategyAny {
		t.Fatalf("unexpected rule: %#v", loaded[0])
	}
}

func TestValidateRulesRejectsDuplicateID(t *testing.T) {
	rule := Rule{
		ID:       "dup",
		Name:     "Duplicate",
		Category: "web",
		Match: MatchBlock{Matchers: []Matcher{
			{Type: "body.contains", Value: "Duplicate"},
		}},
	}
	if err := ValidateRules([]Rule{rule, rule}); err == nil {
		t.Fatalf("ValidateRules() expected duplicate id error")
	}
}

func TestInitLoadsEmbeddedCoreRules(t *testing.T) {
	if err := Init(nil); err != nil {
		t.Fatalf("Init() error: %v", err)
	}

	var found bool
	for _, rule := range ActiveRules() {
		if rule.ID == "core-0048-ollama-api" {
			found = true
			if rule.Category != "ai-service" {
				t.Fatalf("core rule category = %q, want ai-service", rule.Category)
			}
			if len(rule.Metadata.References) == 0 {
				t.Fatalf("core rule should include metadata references")
			}
		}
		if rule.Category == "legacy" {
			t.Fatalf("rule %s was not migrated from legacy category", rule.ID)
		}
	}
	if !found {
		t.Fatalf("embedded core rule was not loaded")
	}
	if len(activeCompiledRules) != len(activeRules) {
		t.Fatalf("compiled rule count = %d, want %d", len(activeCompiledRules), len(activeRules))
	}
	if compiled, ok := activeCompiledFor(ActiveRules()); !ok || len(compiled) != len(activeRules) {
		t.Fatalf("active compiled rules were not reused")
	}
	if activeHTTPProbePlan == nil {
		t.Fatalf("active HTTP probe plan was not built")
	}
}

func TestActiveHTTPProbesReturnsCopy(t *testing.T) {
	if err := Init(nil); err != nil {
		t.Fatalf("Init() error: %v", err)
	}

	probes := ActiveHTTPProbes()
	if len(probes) == 0 {
		t.Fatalf("ActiveHTTPProbes() returned no probes")
	}
	original := probes[0].ID
	probes[0].ID = "mutated-by-test"

	next := ActiveHTTPProbes()
	if next[0].ID != original {
		t.Fatalf("ActiveHTTPProbes() returned mutable plan: got %q, want %q", next[0].ID, original)
	}
}

func TestNormalizeRuleMigratesLegacyMetadata(t *testing.T) {
	rule := NormalizeRule(Rule{
		ID:       "legacy-test",
		Name:     "Grafana",
		Category: "legacy",
		Match: MatchBlock{Matchers: []Matcher{
			{Type: "body.contains", Value: "grafana-app", Evidence: "legacy rule match"},
		}},
	})

	if rule.Category != "observability" {
		t.Fatalf("category = %q, want observability", rule.Category)
	}
	if len(rule.Tags) == 0 || rule.Tags[0] != "migrated" {
		t.Fatalf("tags were not populated: %#v", rule.Tags)
	}
	if len(rule.Metadata.References) != 1 || rule.Metadata.References[0] != migratedLegacyReference {
		t.Fatalf("references were not populated: %#v", rule.Metadata.References)
	}
	if rule.Match.Matchers[0].Evidence == "legacy rule match" || rule.Match.Matchers[0].Evidence == "" {
		t.Fatalf("evidence was not migrated: %#v", rule.Match.Matchers[0])
	}
}

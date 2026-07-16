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

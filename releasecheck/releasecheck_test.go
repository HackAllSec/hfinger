package releasecheck

import (
	"os"
	"path/filepath"
	"testing"
)

func TestChangelogVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "CHANGELOG.md")
	if err := os.WriteFile(path, []byte("# Changelog\n\n## [1.2.3] - 2026-01-01\n"), 0600); err != nil {
		t.Fatalf("WriteFile() error: %v", err)
	}

	version, err := changelogVersion(path)
	if err != nil {
		t.Fatalf("changelogVersion() error: %v", err)
	}
	if version != "1.2.3" {
		t.Fatalf("version = %s, want 1.2.3", version)
	}
}

func TestChangelogVersionRejectsMissingRelease(t *testing.T) {
	path := filepath.Join(t.TempDir(), "CHANGELOG.md")
	if err := os.WriteFile(path, []byte("# Changelog\n"), 0600); err != nil {
		t.Fatalf("WriteFile() error: %v", err)
	}

	if _, err := changelogVersion(path); err == nil {
		t.Fatalf("changelogVersion() error = nil, want error")
	}
}

func TestWinresVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "winres.json")
	data := []byte(`{"RT_MANIFEST":{"#1":{"0409":{"identity":{"name":"hfinger","version":"1.2.3"}}}}}`)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatalf("WriteFile() error: %v", err)
	}

	version, err := winresVersion(path)
	if err != nil {
		t.Fatalf("winresVersion() error: %v", err)
	}
	if version != "1.2.3" {
		t.Fatalf("version = %s, want 1.2.3", version)
	}
}

func TestWinresVersionRejectsMissingIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "winres.json")
	if err := os.WriteFile(path, []byte(`{"RT_MANIFEST":{}}`), 0600); err != nil {
		t.Fatalf("WriteFile() error: %v", err)
	}

	if _, err := winresVersion(path); err == nil {
		t.Fatalf("winresVersion() error = nil, want error")
	}
}

func TestValidateJSONSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rule.schema.json")
	if err := os.WriteFile(path, []byte(`{"$schema":"https://json-schema.org/draft/2020-12/schema"}`), 0600); err != nil {
		t.Fatalf("WriteFile() error: %v", err)
	}

	if err := validateJSONSchema(path); err != nil {
		t.Fatalf("validateJSONSchema() error: %v", err)
	}
}

func TestValidateJSONSchemaRejectsInvalidJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rule.schema.json")
	if err := os.WriteFile(path, []byte(`{"$schema":`), 0600); err != nil {
		t.Fatalf("WriteFile() error: %v", err)
	}

	if err := validateJSONSchema(path); err == nil {
		t.Fatalf("validateJSONSchema() error = nil, want error")
	}
}

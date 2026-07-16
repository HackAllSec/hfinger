package passive

import (
	"path/filepath"
	"testing"

	"hfinger/config"
)

func TestAppendAndQuery(t *testing.T) {
	path := filepath.Join(t.TempDir(), "passive.jsonl")
	SetStorePath(path)
	defer SetStorePath("")

	if err := Append(config.Result{
		URL:        "https://example.com",
		CMS:        "Example",
		Category:   "web",
		Confidence: 90,
	}); err != nil {
		t.Fatalf("Append() error: %v", err)
	}

	records, err := Query(path, QueryFilter{CMS: "Example", MinConfidence: 80})
	if err != nil {
		t.Fatalf("Query() error: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("records length = %d, want 1", len(records))
	}
	if records[0].Result.URL != "https://example.com" {
		t.Fatalf("unexpected record: %#v", records[0])
	}
}

package passive

import (
	"path/filepath"
	"sync"
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

func TestAppendConcurrentAndQueryLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "passive.jsonl")
	SetStorePath(path)
	defer SetStorePath("")

	const workers = 8
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := Append(config.Result{
				URL:        "https://example.com",
				CMS:        "Example",
				Category:   "web",
				Confidence: 90,
			}); err != nil {
				t.Errorf("Append() error: %v", err)
			}
		}()
	}
	wg.Wait()

	records, err := Query(path, QueryFilter{CMS: "Example", Limit: 3})
	if err != nil {
		t.Fatalf("Query() error: %v", err)
	}
	if len(records) != 3 {
		t.Fatalf("records length = %d, want 3", len(records))
	}

	allRecords, err := Query(path, QueryFilter{CMS: "Example"})
	if err != nil {
		t.Fatalf("Query() all records error: %v", err)
	}
	if len(allRecords) != workers {
		t.Fatalf("all records length = %d, want %d", len(allRecords), workers)
	}
}

package passive

import (
	"os"
	"path/filepath"
	"sync"
	"testing"

	"hfinger/config"
)

func TestAppendAndQuery(t *testing.T) {
	path := filepath.Join(t.TempDir(), "passive.jsonl")
	SetStorePath(path)
	defer SetStorePath("")
	SetStoreMaxBytes(0)
	defer SetStoreMaxBytes(0)

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
	SetStoreMaxBytes(0)
	defer SetStoreMaxBytes(0)

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

func TestAppendRotatesStoreWhenMaxBytesExceeded(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "passive.jsonl")
	SetStorePath(path)
	defer SetStorePath("")
	SetStoreMaxBytes(120)
	defer SetStoreMaxBytes(0)

	result := config.Result{
		URL:        "https://example.com/large-passive-record",
		CMS:        "Example",
		Category:   "web",
		Confidence: 90,
	}
	if err := Append(result); err != nil {
		t.Fatalf("Append() first error: %v", err)
	}
	if err := Append(result); err != nil {
		t.Fatalf("Append() second error: %v", err)
	}

	rotated, err := filepath.Glob(filepath.Join(dir, "passive-*.jsonl"))
	if err != nil {
		t.Fatalf("Glob() error: %v", err)
	}
	if len(rotated) != 1 {
		t.Fatalf("rotated files = %d, want 1", len(rotated))
	}
	if _, statErr := os.Stat(path); statErr != nil {
		t.Fatalf("current store stat error: %v", statErr)
	}
	currentRecords, err := Query(path, QueryFilter{CMS: "Example"})
	if err != nil {
		t.Fatalf("Query() current error: %v", err)
	}
	if len(currentRecords) != 1 {
		t.Fatalf("current records length = %d, want 1", len(currentRecords))
	}
	rotatedRecords, err := Query(rotated[0], QueryFilter{CMS: "Example"})
	if err != nil {
		t.Fatalf("Query() rotated error: %v", err)
	}
	if len(rotatedRecords) != 1 {
		t.Fatalf("rotated records length = %d, want 1", len(rotatedRecords))
	}
}

func TestQueryEachStreamsMatchingRecords(t *testing.T) {
	path := filepath.Join(t.TempDir(), "passive.jsonl")
	SetStorePath(path)
	defer SetStorePath("")
	SetStoreMaxBytes(0)
	defer SetStoreMaxBytes(0)

	for i := 0; i < 5; i++ {
		if err := Append(config.Result{
			URL:        "https://example.com",
			CMS:        "Example",
			Category:   "web",
			Confidence: 90,
		}); err != nil {
			t.Fatalf("Append() error: %v", err)
		}
	}

	count := 0
	err := QueryEach(path, QueryFilter{CMS: "Example", Limit: 2}, func(record Record) error {
		count++
		if record.Result.CMS != "Example" {
			t.Fatalf("record CMS = %s, want Example", record.Result.CMS)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("QueryEach() error: %v", err)
	}
	if count != 2 {
		t.Fatalf("streamed records = %d, want 2", count)
	}
}

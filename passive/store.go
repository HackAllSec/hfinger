package passive

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"hfinger/config"
)

type Record struct {
	Time   time.Time     `json:"time"`
	Result config.Result `json:"result"`
}

var storePath string
var storeMaxBytes int64
var storeMu sync.Mutex

func SetStorePath(path string) {
	storeMu.Lock()
	defer storeMu.Unlock()
	storePath = strings.TrimSpace(path)
}

func SetStoreMaxBytes(maxBytes int64) {
	storeMu.Lock()
	defer storeMu.Unlock()
	if maxBytes < 0 {
		maxBytes = 0
	}
	storeMaxBytes = maxBytes
}

func StorePath() string {
	storeMu.Lock()
	defer storeMu.Unlock()
	return storePath
}

func Append(result config.Result) error {
	storeMu.Lock()
	defer storeMu.Unlock()

	path := storePath
	if path == "" {
		return nil
	}
	record := Record{Time: time.Now().UTC(), Result: result}
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	if err := rotateIfNeeded(path, int64(len(data)+1)); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer file.Close()

	if _, err := file.Write(append(data, '\n')); err != nil {
		return err
	}
	return nil
}

func Query(path string, filter QueryFilter) ([]Record, error) {
	var records []Record
	err := QueryEach(path, filter, func(record Record) error {
		records = append(records, record)
		return nil
	})
	return records, err
}

func QueryEach(path string, filter QueryFilter, handle func(Record) error) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	buffer := make([]byte, 0, 1024*1024)
	scanner.Buffer(buffer, 10*1024*1024)
	matched := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var record Record
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			continue
		}
		if filter.Match(record) {
			if err := handle(record); err != nil {
				return err
			}
			matched++
			if filter.Limit > 0 && matched >= filter.Limit {
				break
			}
		}
	}
	return scanner.Err()
}

func rotateIfNeeded(path string, pendingBytes int64) error {
	if storeMaxBytes <= 0 {
		return nil
	}
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if info.Size() == 0 || info.Size()+pendingBytes <= storeMaxBytes {
		return nil
	}
	rotatedPath := rotatedStorePath(path, time.Now().UTC())
	return os.Rename(path, rotatedPath)
}

func rotatedStorePath(path string, now time.Time) string {
	dir := filepath.Dir(path)
	ext := filepath.Ext(path)
	base := strings.TrimSuffix(filepath.Base(path), ext)
	if ext == "" {
		ext = ".jsonl"
	}
	return filepath.Join(dir, fmt.Sprintf("%s-%s%s", base, now.Format("20060102T150405.000000000Z"), ext))
}

type QueryFilter struct {
	URL           string
	CMS           string
	Category      string
	MinConfidence int
	Limit         int
}

func (f QueryFilter) Match(record Record) bool {
	result := record.Result
	if f.URL != "" && !strings.Contains(result.URL, f.URL) {
		return false
	}
	if f.CMS != "" && !strings.EqualFold(result.CMS, f.CMS) {
		return false
	}
	if f.Category != "" && !strings.EqualFold(result.Category, f.Category) {
		return false
	}
	if f.MinConfidence > 0 && result.Confidence < f.MinConfidence {
		return false
	}
	return true
}

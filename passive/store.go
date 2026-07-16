package passive

import (
	"bufio"
	"encoding/json"
	"os"
	"strings"
	"time"

	"hfinger/config"
)

type Record struct {
	Time   time.Time     `json:"time"`
	Result config.Result `json:"result"`
}

var storePath string

func SetStorePath(path string) {
	storePath = strings.TrimSpace(path)
}

func StorePath() string {
	return storePath
}

func Append(result config.Result) error {
	if storePath == "" {
		return nil
	}
	file, err := os.OpenFile(storePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer file.Close()

	record := Record{Time: time.Now().UTC(), Result: result}
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	if _, err := file.Write(append(data, '\n')); err != nil {
		return err
	}
	return nil
}

func Query(path string, filter QueryFilter) ([]Record, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var records []Record
	scanner := bufio.NewScanner(file)
	buffer := make([]byte, 0, 1024*1024)
	scanner.Buffer(buffer, 10*1024*1024)
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
			records = append(records, record)
		}
	}
	return records, scanner.Err()
}

type QueryFilter struct {
	URL           string
	CMS           string
	Category      string
	MinConfidence int
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

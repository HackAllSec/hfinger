package releasecheck

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"

	"hfinger/config"
)

const (
	ChangelogPath = "CHANGELOG.md"
	WinresPath    = "winres/winres.json"
	SchemaPath    = "schemas/rule.schema.json"
)

type Report struct {
	Version          string
	ChangelogVersion string
	WinresVersion    string
	SchemaPath       string
}

func Check() (Report, error) {
	version := strings.TrimPrefix(config.Version, "v")
	report := Report{Version: version, SchemaPath: SchemaPath}

	changelogVersion, err := changelogVersion(ChangelogPath)
	if err != nil {
		return report, err
	}
	report.ChangelogVersion = changelogVersion
	if changelogVersion != version {
		return report, fmt.Errorf("version mismatch: config=%s changelog=%s", version, changelogVersion)
	}

	winresVersion, err := winresVersion(WinresPath)
	if err != nil {
		return report, err
	}
	report.WinresVersion = winresVersion
	if winresVersion != version {
		return report, fmt.Errorf("version mismatch: config=%s winres=%s", version, winresVersion)
	}

	if err := validateJSONSchema(SchemaPath); err != nil {
		return report, err
	}
	return report, nil
}

func changelogVersion(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	re := regexp.MustCompile(`(?m)^## \[([0-9]+\.[0-9]+\.[0-9]+)\]`)
	match := re.FindSubmatch(data)
	if len(match) < 2 {
		return "", fmt.Errorf("no release version found in %s", path)
	}
	return string(match[1]), nil
}

func winresVersion(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	var raw struct {
		RTManifest map[string]map[string]struct {
			Identity struct {
				Version string `json:"version"`
			} `json:"identity"`
		} `json:"RT_MANIFEST"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return "", err
	}
	for _, lang := range raw.RTManifest {
		for _, manifest := range lang {
			if manifest.Identity.Version != "" {
				return manifest.Identity.Version, nil
			}
		}
	}
	return "", fmt.Errorf("no winres identity version found in %s", path)
}

func validateJSONSchema(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("rule schema check failed: %w", err)
	}
	if !json.Valid(data) {
		return fmt.Errorf("rule schema check failed: %s is not valid JSON", path)
	}
	return nil
}

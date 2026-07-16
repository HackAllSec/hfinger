package rules

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"hfinger/rulesets"

	"gopkg.in/yaml.v3"
)

var activeRules []Rule
var activeCompiledRules []compiledRule
var activeHTTPProbePlan []Probe

func Init(paths []string) error {
	var loaded []Rule
	coreRules, err := LoadYAMLFS(rulesets.CoreFS, "core")
	if err != nil {
		return err
	}
	loaded = mergeRules(loaded, NormalizeRules(coreRules))
	for _, path := range paths {
		if strings.TrimSpace(path) == "" {
			continue
		}
		externalRules, err := LoadYAMLPath(path)
		if err != nil {
			return err
		}
		loaded = mergeRules(loaded, externalRules)
	}
	if err := ValidateRules(loaded); err != nil {
		return err
	}
	activeRules = loaded
	activeCompiledRules = compileRules(loaded)
	activeHTTPProbePlan = buildHTTPProbePlan(activeRules)
	return nil
}

func ActiveRules() []Rule {
	if activeRules == nil {
		_ = Init(nil)
	}
	return activeRules
}

func Count() int {
	return len(ActiveRules())
}

func UniqueProductCount() int {
	seen := map[string]struct{}{}
	for _, rule := range ActiveRules() {
		seen[rule.Name] = struct{}{}
	}
	return len(seen)
}

func LoadYAMLPath(path string) ([]Rule, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return LoadYAMLFile(path)
	}

	var loaded []Rule
	err = filepath.WalkDir(path, func(item string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(item))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}
		rules, err := LoadYAMLFile(item)
		if err != nil {
			return fmt.Errorf("%s: %w", item, err)
		}
		loaded = append(loaded, rules...)
		return nil
	})
	return loaded, err
}

func LoadYAMLFile(path string) ([]Rule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseYAMLRules(data)
}

func LoadYAMLFS(fsys fs.FS, root string) ([]Rule, error) {
	var loaded []Rule
	err := fs.WalkDir(fsys, root, func(item string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(item))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}
		data, err := fs.ReadFile(fsys, item)
		if err != nil {
			return err
		}
		rules, err := parseYAMLRules(data)
		if err != nil {
			return fmt.Errorf("%s: %w", item, err)
		}
		loaded = append(loaded, rules...)
		return nil
	})
	return loaded, err
}

func parseYAMLRules(data []byte) ([]Rule, error) {
	var lib Library
	if err := yaml.Unmarshal(data, &lib); err == nil && len(lib.Rules) > 0 {
		return lib.Rules, nil
	}

	var single Rule
	if err := yaml.Unmarshal(data, &single); err != nil {
		return nil, err
	}
	if single.ID == "" && single.Name == "" {
		return nil, errors.New("YAML file does not contain a rule or rules list")
	}
	return []Rule{single}, nil
}

func mergeRules(base []Rule, overlay []Rule) []Rule {
	index := make(map[string]int, len(base))
	for i, rule := range base {
		index[rule.ID] = i
	}
	for _, rule := range overlay {
		if existing, ok := index[rule.ID]; ok {
			base[existing] = rule
			continue
		}
		index[rule.ID] = len(base)
		base = append(base, rule)
	}
	return base
}

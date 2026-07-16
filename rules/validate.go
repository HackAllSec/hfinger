package rules

import (
	"fmt"
	"strings"
)

var supportedMatcherTypes = map[string]struct{}{
	"body.contains":       {},
	"body.regex":          {},
	"header.contains":     {},
	"header.regex":        {},
	"title.contains":      {},
	"cookie.contains":     {},
	"status.eq":           {},
	"status.in":           {},
	"favicon.hash":        {},
	"path.exists":         {},
	"redirect.to":         {},
	"script.src.contains": {},
	"html.meta.contains":  {},
}

func ValidateRules(ruleSet []Rule) error {
	seen := make(map[string]struct{}, len(ruleSet))
	for _, rule := range ruleSet {
		if strings.TrimSpace(rule.ID) == "" {
			return fmt.Errorf("rule id cannot be empty")
		}
		if _, ok := seen[rule.ID]; ok {
			return fmt.Errorf("duplicate rule id: %s", rule.ID)
		}
		seen[rule.ID] = struct{}{}
		if strings.TrimSpace(rule.Name) == "" {
			return fmt.Errorf("rule %s name cannot be empty", rule.ID)
		}
		if strings.TrimSpace(rule.Category) == "" {
			return fmt.Errorf("rule %s category cannot be empty", rule.ID)
		}
		for _, matcher := range rule.Negative {
			if err := validateMatcher(rule.ID, matcher); err != nil {
				return err
			}
		}
		for _, probe := range normalizedProbes(rule) {
			if len(probe.Matchers) == 0 {
				return fmt.Errorf("rule %s probe %s has no matchers", rule.ID, probe.ID)
			}
			for _, matcher := range probe.Matchers {
				if err := validateMatcher(rule.ID, matcher); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func validateMatcher(ruleID string, matcher Matcher) error {
	matcherType := strings.ToLower(strings.TrimSpace(matcher.Type))
	if matcherType == "" {
		return fmt.Errorf("rule %s has matcher without type", ruleID)
	}
	if _, ok := supportedMatcherTypes[matcherType]; !ok {
		return fmt.Errorf("rule %s has unsupported matcher type: %s", ruleID, matcher.Type)
	}
	if matcherType == "path.exists" {
		return nil
	}
	if len(matcherValues(matcher)) == 0 && matcher.Key == "" {
		return fmt.Errorf("rule %s matcher %s has no value", ruleID, matcher.Type)
	}
	return nil
}

package rules

import (
	"fmt"
	"net/http"
	"strings"
)

type LintIssue struct {
	RuleID   string
	Severity string
	Message  string
}

type LintReport struct {
	Rules    int
	Products int
	Errors   []LintIssue
	Warnings []LintIssue
}

func LintRules(ruleSet []Rule) LintReport {
	report := LintReport{Rules: len(ruleSet), Products: uniqueProducts(ruleSet)}
	seen := make(map[string]struct{}, len(ruleSet))
	strongEvidence := map[string]struct{}{
		"header.contains":           {},
		"header.regex":              {},
		"cookie.contains":           {},
		"status.eq":                 {},
		"status.in":                 {},
		"favicon.hash":              {},
		"path.exists":               {},
		"json.key.exists":           {},
		"json.path.eq":              {},
		"tls.cert.subject.contains": {},
		"tls.cert.issuer.contains":  {},
		"tls.cert.dns.contains":     {},
	}

	for _, rule := range ruleSet {
		if strings.TrimSpace(rule.ID) == "" {
			report.Errors = append(report.Errors, issue(rule.ID, "error", "rule id cannot be empty"))
			continue
		}
		if _, ok := seen[rule.ID]; ok {
			report.Errors = append(report.Errors, issue(rule.ID, "error", "duplicate rule id"))
		}
		seen[rule.ID] = struct{}{}
		if strings.TrimSpace(rule.Name) == "" {
			report.Errors = append(report.Errors, issue(rule.ID, "error", "name cannot be empty"))
		}
		if strings.TrimSpace(rule.Category) == "" {
			report.Errors = append(report.Errors, issue(rule.ID, "error", "category cannot be empty"))
		}
		if len(rule.Metadata.References) == 0 {
			report.Warnings = append(report.Warnings, issue(rule.ID, "warning", "metadata.references is recommended"))
		}
		if len(rule.Negative) == 0 {
			report.Warnings = append(report.Warnings, issue(rule.ID, "warning", "negative matchers are recommended for reducing false positives"))
		}

		hasStrongEvidence := false
		for _, matcher := range collectMatchers(rule) {
			matcherType := strings.ToLower(strings.TrimSpace(matcher.Type))
			if _, ok := supportedMatcherTypes[matcherType]; !ok {
				report.Errors = append(report.Errors, issue(rule.ID, "error", fmt.Sprintf("unsupported matcher type: %s", matcher.Type)))
				continue
			}
			if matcherType != "path.exists" && len(matcherValues(matcher)) == 0 && matcher.Key == "" {
				report.Errors = append(report.Errors, issue(rule.ID, "error", fmt.Sprintf("matcher %s has no value", matcher.Type)))
			}
			if _, ok := strongEvidence[matcherType]; ok {
				hasStrongEvidence = true
			}
			for _, value := range matcherValues(matcher) {
				if isWeakValue(matcherType, value) {
					report.Warnings = append(report.Warnings, issue(rule.ID, "warning", fmt.Sprintf("weak matcher value for %s: %q", matcher.Type, value)))
				}
			}
		}
		if !hasStrongEvidence {
			report.Warnings = append(report.Warnings, issue(rule.ID, "warning", "rule has no strong evidence matcher"))
		}
	}
	return report
}

func (r LintReport) HasErrors() bool {
	return len(r.Errors) > 0
}

func ValidateRules(ruleSet []Rule) error {
	report := LintRules(ruleSet)
	if len(report.Errors) == 0 {
		return nil
	}
	first := report.Errors[0]
	return fmt.Errorf("rule %s: %s", first.RuleID, first.Message)
}

func TestRules(ruleSet []Rule) []LintIssue {
	var failures []LintIssue
	for _, rule := range ruleSet {
		for _, fixture := range rule.Examples.Positive {
			response := fixtureResponse(fixture)
			result := MatchRule([]Response{response}, rule)
			if !result.Matched {
				failures = append(failures, issue(rule.ID, "error", fmt.Sprintf("positive fixture %q did not match", fixtureName(fixture))))
			}
		}
		for _, fixture := range rule.Examples.Negative {
			response := fixtureResponse(fixture)
			result := MatchRule([]Response{response}, rule)
			if result.Matched {
				failures = append(failures, issue(rule.ID, "error", fmt.Sprintf("negative fixture %q matched unexpectedly", fixtureName(fixture))))
			}
		}
	}
	return failures
}

func collectMatchers(rule Rule) []Matcher {
	matchers := make([]Matcher, 0)
	matchers = append(matchers, rule.Negative...)
	for _, probe := range normalizedProbes(rule) {
		matchers = append(matchers, probe.Matchers...)
	}
	return matchers
}

func uniqueProducts(ruleSet []Rule) int {
	seen := map[string]struct{}{}
	for _, rule := range ruleSet {
		seen[rule.Name] = struct{}{}
	}
	return len(seen)
}

func issue(ruleID, severity, message string) LintIssue {
	return LintIssue{RuleID: ruleID, Severity: severity, Message: message}
}

func isWeakValue(matcherType, value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return true
	}
	if strings.Contains(matcherType, "regex") {
		return false
	}
	return len([]rune(value)) < 4
}

func fixtureResponse(fixture Fixture) Response {
	header := http.Header{}
	for key, value := range fixture.Headers {
		header.Set(key, value)
	}
	if fixture.Server != "" {
		header.Set("Server", fixture.Server)
	}
	path := fixture.Path
	if path == "" {
		path = PathFromURL(fixture.URL)
	}
	return Response{
		ProbeID:    "fixture",
		URL:        fixture.URL,
		Path:       path,
		StatusCode: fixture.StatusCode,
		Server:     fixture.Server,
		Title:      fixture.Title,
		Header:     header,
		Body:       []byte(fixture.Body),
		TLS:        fixture.TLS,
	}
}

func fixtureName(fixture Fixture) string {
	if fixture.Name != "" {
		return fixture.Name
	}
	if fixture.URL != "" {
		return fixture.URL
	}
	return fixture.Path
}

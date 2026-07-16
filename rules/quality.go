package rules

import (
	"fmt"
	"net/http"
	"slices"
	"sort"
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

type StatsReport struct {
	Rules              int
	Products           int
	Categories         map[string]int
	Tiers              map[string]int
	LintErrors         int
	LintWarnings       int
	LintErrorsByTier   map[string]int
	LintWarningsByTier map[string]int
}

type DoctorReport struct {
	Stats   StatsReport
	Issues  []DoctorIssueSummary
	Rules   []DoctorRuleSummary
	HasMore bool
}

type DoctorIssueSummary struct {
	Severity string
	Message  string
	Count    int
}

type DoctorRuleSummary struct {
	RuleID      string
	Name        string
	Category    string
	Tier        string
	Errors      int
	Warnings    int
	Suggestions []string
}

func Stats(ruleSet []Rule) StatsReport {
	report := StatsReport{
		Rules:              len(ruleSet),
		Products:           uniqueProducts(ruleSet),
		Categories:         make(map[string]int),
		Tiers:              make(map[string]int),
		LintErrorsByTier:   make(map[string]int),
		LintWarningsByTier: make(map[string]int),
	}
	ruleTiers := make(map[string]string, len(ruleSet))
	for _, rule := range ruleSet {
		tier := RuleTier(rule)
		report.Categories[rule.Category]++
		report.Tiers[tier]++
		ruleTiers[rule.ID] = tier
	}
	lintReport := LintRules(ruleSet)
	report.LintErrors = len(lintReport.Errors)
	report.LintWarnings = len(lintReport.Warnings)
	for _, lintError := range lintReport.Errors {
		report.LintErrorsByTier[ruleTierForIssue(ruleTiers, lintError)]++
	}
	for _, lintWarning := range lintReport.Warnings {
		report.LintWarningsByTier[ruleTierForIssue(ruleTiers, lintWarning)]++
	}
	return report
}

func Doctor(ruleSet []Rule, maxRules int) DoctorReport {
	stats := Stats(ruleSet)
	lintReport := LintRules(ruleSet)
	ruleIndex := make(map[string]Rule, len(ruleSet))
	for _, rule := range ruleSet {
		ruleIndex[rule.ID] = rule
	}

	issueCounts := make(map[string]DoctorIssueSummary)
	ruleSummaries := make(map[string]*DoctorRuleSummary)
	addIssue := func(item LintIssue) {
		key := item.Severity + "\x00" + item.Message
		summary := issueCounts[key]
		summary.Severity = item.Severity
		summary.Message = item.Message
		summary.Count++
		issueCounts[key] = summary

		rule, ok := ruleIndex[item.RuleID]
		if !ok {
			rule = Rule{ID: item.RuleID}
		}
		ruleSummary := ruleSummaries[item.RuleID]
		if ruleSummary == nil {
			ruleSummary = &DoctorRuleSummary{
				RuleID:   item.RuleID,
				Name:     rule.Name,
				Category: rule.Category,
				Tier:     RuleTier(rule),
			}
			ruleSummaries[item.RuleID] = ruleSummary
		}
		if item.Severity == "error" {
			ruleSummary.Errors++
		} else {
			ruleSummary.Warnings++
		}
		addSuggestion(ruleSummary, item.Message)
	}
	for _, item := range lintReport.Errors {
		addIssue(item)
	}
	for _, item := range lintReport.Warnings {
		addIssue(item)
	}

	issues := make([]DoctorIssueSummary, 0, len(issueCounts))
	for _, issue := range issueCounts {
		issues = append(issues, issue)
	}
	sort.Slice(issues, func(i, j int) bool {
		if issues[i].Count != issues[j].Count {
			return issues[i].Count > issues[j].Count
		}
		if issues[i].Severity != issues[j].Severity {
			return issues[i].Severity < issues[j].Severity
		}
		return issues[i].Message < issues[j].Message
	})

	rules := make([]DoctorRuleSummary, 0, len(ruleSummaries))
	for _, ruleSummary := range ruleSummaries {
		rules = append(rules, *ruleSummary)
	}
	sort.Slice(rules, func(i, j int) bool {
		if rules[i].Errors != rules[j].Errors {
			return rules[i].Errors > rules[j].Errors
		}
		if rules[i].Warnings != rules[j].Warnings {
			return rules[i].Warnings > rules[j].Warnings
		}
		return rules[i].RuleID < rules[j].RuleID
	})
	hasMore := false
	if maxRules >= 0 && len(rules) > maxRules {
		rules = rules[:maxRules]
		hasMore = true
	}

	return DoctorReport{Stats: stats, Issues: issues, Rules: rules, HasMore: hasMore}
}

func addSuggestion(ruleSummary *DoctorRuleSummary, message string) {
	suggestion := doctorSuggestion(message)
	if suggestion == "" {
		return
	}
	if slices.Contains(ruleSummary.Suggestions, suggestion) {
		return
	}
	ruleSummary.Suggestions = append(ruleSummary.Suggestions, suggestion)
}

func doctorSuggestion(message string) string {
	switch {
	case strings.Contains(message, "negative matchers"):
		return "add negative matchers to reduce false positives"
	case strings.Contains(message, "no strong evidence matcher"):
		return "add a strong evidence matcher such as header.contains, favicon.hash, json.key.exists, or tls.cert.*"
	case strings.Contains(message, "weak matcher value"):
		return "replace weak keywords with longer product-specific evidence"
	case strings.Contains(message, "metadata.references"):
		return "add upstream documentation or product references"
	case strings.Contains(message, "unsupported matcher type"):
		return "replace unsupported matcher types with the documented YAML schema"
	case strings.Contains(message, "has no value"):
		return "set matcher value, values, key, or use path.exists where appropriate"
	case strings.Contains(message, "duplicate rule id"):
		return "assign a unique rule id"
	case strings.Contains(message, "cannot be empty"):
		return "fill the required rule metadata field"
	default:
		return ""
	}
}

func RuleTier(rule Rule) string {
	switch {
	case strings.HasPrefix(rule.ID, "core-"):
		return "curated"
	case strings.HasPrefix(rule.ID, "builtin-"):
		return "migrated"
	default:
		return "external"
	}
}

func ruleTierForIssue(ruleTiers map[string]string, lintIssue LintIssue) string {
	if tier, ok := ruleTiers[lintIssue.RuleID]; ok {
		return tier
	}
	return "external"
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
		"favicon.hash.md5":          {},
		"favicon.hash.sha1":         {},
		"favicon.hash.sha256":       {},
		"path.exists":               {},
		"script.hash.md5":           {},
		"script.hash.sha1":          {},
		"script.hash.sha256":        {},
		"json.key.exists":           {},
		"json.path.eq":              {},
		"tls.cert.subject.contains": {},
		"tls.cert.issuer.contains":  {},
		"tls.cert.dns.contains":     {},
		"tls.cipher.contains":       {},
		"tls.ja3s.hash":             {},
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
			if !valueOptionalMatcher(matcherType) && len(matcherValues(matcher)) == 0 && matcher.Key == "" {
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
		if !hasStrongEvidence && !hasCorroboratedEvidence(rule) {
			report.Warnings = append(report.Warnings, issue(rule.ID, "warning", "rule has no strong evidence matcher"))
		}
	}
	return report
}

func valueOptionalMatcher(matcherType string) bool {
	switch matcherType {
	case "path.exists", "response.etag.exists", "response.accept_ranges.exists":
		return true
	default:
		return false
	}
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

func hasCorroboratedEvidence(rule Rule) bool {
	if len(rule.Negative) == 0 || len(rule.Metadata.References) == 0 {
		return false
	}
	positiveMatchers := 0
	sources := map[string]struct{}{}
	for _, probe := range normalizedProbes(rule) {
		for _, matcher := range probe.Matchers {
			positiveMatchers++
			sources[matcherSource(matcher.Type)] = struct{}{}
		}
	}
	return positiveMatchers >= 2 && len(sources) >= 1
}

func matcherSource(matcherType string) string {
	matcherType = strings.ToLower(strings.TrimSpace(matcherType))
	if source, _, ok := strings.Cut(matcherType, "."); ok {
		return source
	}
	return matcherType
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

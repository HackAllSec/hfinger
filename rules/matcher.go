package rules

import (
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/twmb/murmur3"
)

func MatchRules(responses []Response, ruleSet []Rule) []MatchResult {
	results := make([]MatchResult, 0)
	for _, rule := range ruleSet {
		result := MatchRule(responses, rule)
		if result.Matched {
			results = append(results, result)
		}
	}
	return results
}

func MatchRule(responses []Response, rule Rule) MatchResult {
	result := MatchResult{Rule: rule}
	if len(responses) == 0 {
		return result
	}

	for _, negative := range rule.Negative {
		if evidence, ok := matchAnyResponse(responses, negative); ok {
			result.Excluded = true
			result.ExcludeBy = append(result.ExcludeBy, evidence)
			return result
		}
	}

	probes := normalizedProbes(rule)
	strategy := normalizedStrategy(rule.Match.Strategy)
	threshold := rule.Match.Threshold
	if threshold <= 0 {
		threshold = 100
	}

	totalPossible := 0
	totalScore := 0
	allMatched := true
	anyMatched := false

	for _, probe := range probes {
		candidates := filterResponsesForProbe(responses, probe)
		if len(candidates) == 0 {
			allMatched = false
			continue
		}

		for _, matcher := range probe.Matchers {
			weight := matcherWeight(matcher)
			totalPossible += weight
			evidence, ok := matchAnyResponse(candidates, matcher)
			if !ok {
				allMatched = false
				continue
			}
			anyMatched = true
			totalScore += weight
			evidence.Weight = weight
			result.Evidence = append(result.Evidence, evidence)
			if result.Response.URL == "" {
				result.Response = findEvidenceResponse(responses, evidence.ResponseURL)
			}
		}
	}

	switch strategy {
	case StrategyAll:
		result.Matched = allMatched && anyMatched
	case StrategyAny:
		result.Matched = anyMatched
	default:
		result.Matched = totalScore >= threshold
	}

	result.Score = totalScore
	result.Confidence = confidence(totalScore, totalPossible, threshold, strategy)
	return result
}

func normalizedProbes(rule Rule) []Probe {
	if len(rule.Match.Probes) > 0 {
		return rule.Match.Probes
	}
	return []Probe{{
		ID:       "default",
		Matchers: rule.Match.Matchers,
	}}
}

func normalizedStrategy(strategy string) string {
	switch strings.ToLower(strategy) {
	case StrategyAny:
		return StrategyAny
	case StrategyAll:
		return StrategyAll
	default:
		return StrategyScore
	}
}

func matcherWeight(matcher Matcher) int {
	if matcher.Weight > 0 {
		return matcher.Weight
	}
	return 100
}

func confidence(score, totalPossible, threshold int, strategy string) int {
	if score <= 0 {
		return 0
	}
	switch strategy {
	case StrategyAny:
		return 100
	case StrategyAll:
		if totalPossible <= 0 {
			return 100
		}
		return min(100, score*100/totalPossible)
	default:
		return min(100, score*100/threshold)
	}
}

func filterResponsesForProbe(responses []Response, probe Probe) []Response {
	path := probe.Request.Path
	if path == "" {
		return responses
	}
	filtered := make([]Response, 0, len(responses))
	for _, response := range responses {
		if response.ProbeID == probe.ID || response.Path == path {
			filtered = append(filtered, response)
		}
	}
	return filtered
}

func matchAnyResponse(responses []Response, matcher Matcher) (Evidence, bool) {
	for _, response := range responses {
		if evidence, ok := MatchResponse(response, matcher); ok {
			return evidence, true
		}
	}
	return Evidence{}, false
}

func MatchResponse(response Response, matcher Matcher) (Evidence, bool) {
	values := matcherValues(matcher)
	switch strings.ToLower(matcher.Type) {
	case "body.contains":
		return matchText("body", matcher, string(response.Body), values, response.URL)
	case "body.regex":
		return matchRegex("body", matcher, string(response.Body), values, response.URL)
	case "header.contains":
		return matchHeaderContains(response.Header, matcher, values, response.URL)
	case "header.regex":
		return matchHeaderRegex(response.Header, matcher, values, response.URL)
	case "title.contains":
		return matchText("title", matcher, response.Title, values, response.URL)
	case "cookie.contains":
		return matchHeaderContains(response.Header, Matcher{
			Type:          matcher.Type,
			Key:           "Set-Cookie",
			Value:         matcher.Value,
			Values:        matcher.Values,
			Weight:        matcher.Weight,
			Evidence:      matcher.Evidence,
			CaseSensitive: matcher.CaseSensitive,
		}, values, response.URL)
	case "status.eq":
		return matchStatus(response, matcher, values, false)
	case "status.in":
		return matchStatus(response, matcher, values, true)
	case "favicon.hash":
		return matchFavicon(response, matcher, values)
	case "redirect.to":
		return matchText("redirect", matcher, response.Header.Get("Location"), values, response.URL)
	case "script.src.contains":
		return matchRegex("script.src", matcher, string(response.Body), scriptPatterns(values), response.URL)
	case "html.meta.contains":
		return matchRegex("html.meta", matcher, string(response.Body), metaPatterns(values), response.URL)
	case "path.exists":
		if response.StatusCode >= 200 && response.StatusCode < 400 {
			return evidence("path", matcher, response.Path, response.URL), true
		}
	}
	return Evidence{}, false
}

func matcherValues(matcher Matcher) []string {
	if len(matcher.Values) > 0 {
		return matcher.Values
	}
	switch value := matcher.Value.(type) {
	case string:
		return []string{value}
	case int:
		return []string{strconv.Itoa(value)}
	case int64:
		return []string{strconv.FormatInt(value, 10)}
	case float64:
		return []string{strconv.Itoa(int(value))}
	case []interface{}:
		values := make([]string, 0, len(value))
		for _, item := range value {
			values = append(values, fmt.Sprint(item))
		}
		return values
	case nil:
		return nil
	default:
		return []string{fmt.Sprint(value)}
	}
}

func matchText(source string, matcher Matcher, target string, values []string, responseURL string) (Evidence, bool) {
	targetToMatch := target
	if !isCaseSensitive(matcher) {
		targetToMatch = strings.ToLower(target)
	}
	for _, value := range values {
		valueToMatch := value
		if !isCaseSensitive(matcher) {
			valueToMatch = strings.ToLower(value)
		}
		if strings.Contains(targetToMatch, valueToMatch) {
			return evidence(source, matcher, snippet(target, value), responseURL), true
		}
	}
	return Evidence{}, false
}

func matchRegex(source string, matcher Matcher, target string, values []string, responseURL string) (Evidence, bool) {
	for _, value := range values {
		re, err := regexp.Compile(value)
		if err != nil {
			continue
		}
		match := re.FindString(target)
		if match != "" {
			return evidence(source, matcher, truncate(match, 160), responseURL), true
		}
	}
	return Evidence{}, false
}

func matchHeaderContains(headers http.Header, matcher Matcher, values []string, responseURL string) (Evidence, bool) {
	for key, headerValues := range headers {
		if matcher.Key != "" && !strings.EqualFold(key, matcher.Key) {
			continue
		}
		if matcher.Key != "" && len(values) == 0 {
			return evidence("header", matcher, key, responseURL), true
		}
		for _, headerValue := range headerValues {
			if ev, ok := matchText("header", matcher, key+": "+headerValue, values, responseURL); ok {
				return ev, true
			}
		}
		if matcher.Key == "" {
			if ev, ok := matchText("header", matcher, key, values, responseURL); ok {
				return ev, true
			}
		}
	}
	return Evidence{}, false
}

func matchHeaderRegex(headers http.Header, matcher Matcher, values []string, responseURL string) (Evidence, bool) {
	for key, headerValues := range headers {
		if matcher.Key != "" && !strings.EqualFold(key, matcher.Key) {
			continue
		}
		for _, headerValue := range headerValues {
			if ev, ok := matchRegex("header", matcher, key+": "+headerValue, values, responseURL); ok {
				return ev, true
			}
		}
	}
	return Evidence{}, false
}

func matchStatus(response Response, matcher Matcher, values []string, in bool) (Evidence, bool) {
	status := strconv.Itoa(response.StatusCode)
	for _, value := range values {
		if status == value {
			return evidence("status", matcher, status, response.URL), true
		}
	}
	return Evidence{}, false
}

func matchFavicon(response Response, matcher Matcher, values []string) (Evidence, bool) {
	if len(response.Favicon) == 0 {
		return Evidence{}, false
	}
	hash := int32(murmur3.SeedSum32(0, response.Favicon))
	hashText := strconv.FormatInt(int64(hash), 10)
	for _, value := range values {
		if hashText == value {
			return evidence("favicon", matcher, hashText, response.URL), true
		}
	}
	return Evidence{}, false
}

func scriptPatterns(values []string) []string {
	patterns := make([]string, 0, len(values))
	for _, value := range values {
		patterns = append(patterns, `(?is)<script[^>]+src=["'][^"']*`+regexp.QuoteMeta(value)+`[^"']*["']`)
	}
	return patterns
}

func metaPatterns(values []string) []string {
	patterns := make([]string, 0, len(values))
	for _, value := range values {
		patterns = append(patterns, `(?is)<meta[^>]+`+regexp.QuoteMeta(value)+`[^>]*>`)
	}
	return patterns
}

func isCaseSensitive(matcher Matcher) bool {
	if matcher.CaseSensitive == nil {
		return true
	}
	return *matcher.CaseSensitive
}

func evidence(source string, matcher Matcher, matchedValue string, responseURL string) Evidence {
	message := matcher.Evidence
	if message == "" {
		message = matcher.Reason
	}
	return Evidence{
		Source:       source,
		MatcherType:  matcher.Type,
		Key:          matcher.Key,
		MatchedValue: matchedValue,
		Weight:       matcherWeight(matcher),
		Message:      message,
		ResponseURL:  responseURL,
	}
}

func snippet(target, needle string) string {
	if needle == "" {
		return truncate(target, 160)
	}
	idx := strings.Index(target, needle)
	if idx < 0 {
		return truncate(target, 160)
	}
	start := max(0, idx-40)
	end := min(len(target), idx+len(needle)+40)
	return truncate(target[start:end], 160)
}

func truncate(value string, limit int) string {
	value = strings.TrimSpace(value)
	if len(value) <= limit {
		return value
	}
	return value[:limit] + "..."
}

func findEvidenceResponse(responses []Response, responseURL string) Response {
	for _, response := range responses {
		if response.URL == responseURL {
			return response
		}
	}
	return responses[0]
}

func PathFromURL(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Path == "" {
		return "/"
	}
	return parsed.Path
}

package rules

import (
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

func MatchRules(responses []Response, ruleSet []Rule) []MatchResult {
	if compiled, ok := activeCompiledFor(ruleSet); ok {
		return matchCompiledRules(responses, compiled)
	}
	return matchCompiledRules(responses, compileRules(ruleSet))
}

func MatchRule(responses []Response, rule Rule) MatchResult {
	return matchCompiledRule(prepareResponses(responses), compileRule(rule))
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
		if totalPossible <= 0 {
			return 100
		}
		return min(100, score*100/totalPossible)
	case StrategyAll:
		if totalPossible <= 0 {
			return 100
		}
		return min(100, score*100/totalPossible)
	default:
		return min(100, score*100/threshold)
	}
}

func MatchResponse(response Response, matcher Matcher) (Evidence, bool) {
	prepared := prepareResponses([]Response{response})
	return matchPreparedResponse(prepared[0], compileMatcher(matcher))
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

func jsonKeyExists(data interface{}, key string) bool {
	switch value := data.(type) {
	case map[string]interface{}:
		if _, ok := value[key]; ok {
			return true
		}
		for _, child := range value {
			if jsonKeyExists(child, key) {
				return true
			}
		}
	case []interface{}:
		for _, child := range value {
			if jsonKeyExists(child, key) {
				return true
			}
		}
	}
	return false
}

func jsonPathValue(data interface{}, parts []string) (interface{}, bool) {
	if len(parts) == 0 {
		return data, true
	}
	obj, ok := data.(map[string]interface{})
	if !ok {
		return nil, false
	}
	next, ok := obj[parts[0]]
	if !ok {
		return nil, false
	}
	return jsonPathValue(next, parts[1:])
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

func PathFromURL(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Path == "" {
		return "/"
	}
	return parsed.Path
}

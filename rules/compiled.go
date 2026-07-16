package rules

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/twmb/murmur3"
)

type compiledRule struct {
	rule          Rule
	probes        []compiledProbe
	negative      []compiledMatcher
	extractors    []compiledExtractor
	strategy      string
	threshold     int
	totalPossible int
}

type compiledProbe struct {
	probe    Probe
	matchers []compiledMatcher
}

type compiledMatcher struct {
	matcher     Matcher
	matcherType string
	values      []string
	lowerValues []string
	regexps     []*regexp.Regexp
	statusCodes map[int]struct{}
	weight      int
}

type compiledExtractor struct {
	extractor Extractor
	regex     *regexp.Regexp
}

type preparedResponse struct {
	response Response

	body      string
	lowerBody string

	title      string
	lowerTitle string

	server      string
	lowerServer string

	redirect      string
	lowerRedirect string

	tlsSubject      string
	lowerTLSSubject string
	tlsIssuer       string
	lowerTLSIssuer  string
	tlsDNS          string
	lowerTLSDNS     string
	tlsALPN         string
	lowerTLSALPN    string

	faviconHash string

	jsonParsed bool
	jsonOK     bool
	jsonData   interface{}
}

func compileRules(ruleSet []Rule) []compiledRule {
	compiled := make([]compiledRule, 0, len(ruleSet))
	for _, rule := range ruleSet {
		compiled = append(compiled, compileRule(rule))
	}
	return compiled
}

func compileRule(rule Rule) compiledRule {
	threshold := rule.Match.Threshold
	if threshold <= 0 {
		threshold = 100
	}

	compiled := compiledRule{
		rule:      rule,
		strategy:  normalizedStrategy(rule.Match.Strategy),
		threshold: threshold,
	}
	for _, matcher := range rule.Negative {
		compiled.negative = append(compiled.negative, compileMatcher(matcher))
	}
	for _, probe := range normalizedProbes(rule) {
		compiledProbe := compiledProbe{probe: probe}
		for _, matcher := range probe.Matchers {
			cm := compileMatcher(matcher)
			compiledProbe.matchers = append(compiledProbe.matchers, cm)
			compiled.totalPossible += cm.weight
		}
		compiled.probes = append(compiled.probes, compiledProbe)
	}
	for _, extractor := range rule.Extract {
		if strings.TrimSpace(extractor.Regex) == "" {
			continue
		}
		re, err := regexp.Compile(extractor.Regex)
		if err != nil {
			continue
		}
		compiled.extractors = append(compiled.extractors, compiledExtractor{
			extractor: extractor,
			regex:     re,
		})
	}
	return compiled
}

func compileMatcher(matcher Matcher) compiledMatcher {
	values := matcherValues(matcher)
	cm := compiledMatcher{
		matcher:     matcher,
		matcherType: strings.ToLower(strings.TrimSpace(matcher.Type)),
		values:      values,
		lowerValues: make([]string, 0, len(values)),
		weight:      matcherWeight(matcher),
	}
	for _, value := range values {
		cm.lowerValues = append(cm.lowerValues, strings.ToLower(value))
	}

	switch cm.matcherType {
	case "body.regex", "header.regex", "server.banner.regex":
		cm.regexps = compileRegexps(values)
	case "script.src.contains":
		cm.regexps = compileRegexps(scriptPatterns(values))
	case "html.meta.contains":
		cm.regexps = compileRegexps(metaPatterns(values))
	case "status.eq", "status.in":
		cm.statusCodes = make(map[int]struct{}, len(values))
		for _, value := range values {
			status, err := strconv.Atoi(value)
			if err != nil {
				continue
			}
			cm.statusCodes[status] = struct{}{}
		}
	}
	return cm
}

func compileRegexps(values []string) []*regexp.Regexp {
	regexps := make([]*regexp.Regexp, 0, len(values))
	for _, value := range values {
		re, err := regexp.Compile(value)
		if err != nil {
			continue
		}
		regexps = append(regexps, re)
	}
	return regexps
}

func activeCompiledFor(ruleSet []Rule) ([]compiledRule, bool) {
	if len(ruleSet) == 0 || len(ruleSet) != len(activeRules) || len(activeCompiledRules) != len(activeRules) {
		return nil, false
	}
	return activeCompiledRules, &ruleSet[0] == &activeRules[0]
}

func prepareResponses(responses []Response) []*preparedResponse {
	prepared := make([]*preparedResponse, 0, len(responses))
	for _, response := range responses {
		body := string(response.Body)
		tlsDNS := strings.Join(response.TLS.DNSNames, ",")
		faviconHash := ""
		if len(response.Favicon) > 0 {
			hash := int32(murmur3.SeedSum32(0, response.Favicon))
			faviconHash = strconv.FormatInt(int64(hash), 10)
		}
		prepared = append(prepared, &preparedResponse{
			response: response,

			body:      body,
			lowerBody: strings.ToLower(body),

			title:      response.Title,
			lowerTitle: strings.ToLower(response.Title),

			server:      response.Server,
			lowerServer: strings.ToLower(response.Server),

			redirect:      response.Header.Get("Location"),
			lowerRedirect: strings.ToLower(response.Header.Get("Location")),

			tlsSubject:      response.TLS.Subject,
			lowerTLSSubject: strings.ToLower(response.TLS.Subject),
			tlsIssuer:       response.TLS.Issuer,
			lowerTLSIssuer:  strings.ToLower(response.TLS.Issuer),
			tlsDNS:          tlsDNS,
			lowerTLSDNS:     strings.ToLower(tlsDNS),
			tlsALPN:         response.TLS.ALPN,
			lowerTLSALPN:    strings.ToLower(response.TLS.ALPN),

			faviconHash: faviconHash,
		})
	}
	return prepared
}

func matchCompiledRules(responses []Response, compiled []compiledRule) []MatchResult {
	prepared := prepareResponses(responses)
	results := make([]MatchResult, 0)
	for _, rule := range compiled {
		result := matchCompiledRule(prepared, rule)
		if result.Matched {
			results = append(results, result)
		}
	}
	return results
}

func matchCompiledRule(responses []*preparedResponse, rule compiledRule) MatchResult {
	result := MatchResult{Rule: rule.rule}
	if len(responses) == 0 {
		return result
	}

	for _, negative := range rule.negative {
		if evidence, ok := matchAnyPreparedResponse(responses, negative); ok {
			result.Excluded = true
			result.ExcludeBy = append(result.ExcludeBy, evidence)
			return result
		}
	}

	totalScore := 0
	allMatched := true
	anyMatched := false

	for _, probe := range rule.probes {
		candidates := filterPreparedResponsesForProbe(responses, probe.probe)
		if len(candidates) == 0 {
			allMatched = false
			continue
		}

		for _, matcher := range probe.matchers {
			evidence, ok := matchAnyPreparedResponse(candidates, matcher)
			if !ok {
				allMatched = false
				continue
			}
			anyMatched = true
			totalScore += matcher.weight
			evidence.Weight = matcher.weight
			result.Evidence = append(result.Evidence, evidence)
			if result.Response.URL == "" {
				result.Response = findPreparedEvidenceResponse(responses, evidence.ResponseURL)
			}
		}
	}

	switch rule.strategy {
	case StrategyAll:
		result.Matched = allMatched && anyMatched
	case StrategyAny:
		result.Matched = anyMatched
	default:
		result.Matched = totalScore >= rule.threshold
	}

	result.Score = totalScore
	result.Confidence = confidence(totalScore, rule.totalPossible, rule.threshold, rule.strategy)
	if result.Matched {
		result.Version = extractCompiledVersion(responses, rule)
	}
	return result
}

func filterPreparedResponsesForProbe(responses []*preparedResponse, probe Probe) []*preparedResponse {
	path := probe.Request.Path
	if path == "" {
		return responses
	}
	filtered := make([]*preparedResponse, 0, len(responses))
	for _, response := range responses {
		if response.response.ProbeID == probe.ID || response.response.Path == path {
			filtered = append(filtered, response)
		}
	}
	return filtered
}

func matchAnyPreparedResponse(responses []*preparedResponse, matcher compiledMatcher) (Evidence, bool) {
	for _, response := range responses {
		if evidence, ok := matchPreparedResponse(response, matcher); ok {
			return evidence, true
		}
	}
	return Evidence{}, false
}

func matchPreparedResponse(response *preparedResponse, matcher compiledMatcher) (Evidence, bool) {
	switch matcher.matcherType {
	case "body.contains":
		return matchPreparedText("body", matcher, response.body, response.lowerBody, response.response.URL)
	case "body.regex":
		return matchPreparedRegex("body", matcher, response.body, response.response.URL)
	case "header.contains":
		return matchPreparedHeaderContains(response.response.Header, matcher, response.response.URL)
	case "header.regex":
		return matchPreparedHeaderRegex(response.response.Header, matcher, response.response.URL)
	case "title.contains":
		return matchPreparedText("title", matcher, response.title, response.lowerTitle, response.response.URL)
	case "cookie.contains":
		cookieMatcher := matcher
		cookieMatcher.matcher.Key = "Set-Cookie"
		return matchPreparedHeaderContains(response.response.Header, cookieMatcher, response.response.URL)
	case "status.eq", "status.in":
		if _, ok := matcher.statusCodes[response.response.StatusCode]; ok {
			return evidence("status", matcher.matcher, strconv.Itoa(response.response.StatusCode), response.response.URL), true
		}
	case "favicon.hash":
		if response.faviconHash == "" {
			return Evidence{}, false
		}
		for _, value := range matcher.values {
			if response.faviconHash == value {
				return evidence("favicon", matcher.matcher, response.faviconHash, response.response.URL), true
			}
		}
	case "redirect.to":
		return matchPreparedText("redirect", matcher, response.redirect, response.lowerRedirect, response.response.URL)
	case "script.src.contains":
		return matchPreparedRegex("script.src", matcher, response.body, response.response.URL)
	case "html.meta.contains":
		return matchPreparedRegex("html.meta", matcher, response.body, response.response.URL)
	case "path.exists":
		if response.response.StatusCode >= 200 && response.response.StatusCode < 400 {
			return evidence("path", matcher.matcher, response.response.Path, response.response.URL), true
		}
	case "json.key.exists":
		return matchPreparedJSONKey(response, matcher)
	case "json.path.eq":
		return matchPreparedJSONPath(response, matcher)
	case "server.banner.contains":
		return matchPreparedText("server", matcher, response.server, response.lowerServer, response.response.URL)
	case "server.banner.regex":
		return matchPreparedRegex("server", matcher, response.server, response.response.URL)
	case "tls.cert.subject.contains":
		return matchPreparedText("tls.cert.subject", matcher, response.tlsSubject, response.lowerTLSSubject, response.response.URL)
	case "tls.cert.issuer.contains":
		return matchPreparedText("tls.cert.issuer", matcher, response.tlsIssuer, response.lowerTLSIssuer, response.response.URL)
	case "tls.cert.dns.contains":
		return matchPreparedText("tls.cert.dns", matcher, response.tlsDNS, response.lowerTLSDNS, response.response.URL)
	case "tls.alpn.contains":
		return matchPreparedText("tls.alpn", matcher, response.tlsALPN, response.lowerTLSALPN, response.response.URL)
	}
	return Evidence{}, false
}

func matchPreparedText(source string, matcher compiledMatcher, target string, lowerTarget string, responseURL string) (Evidence, bool) {
	values := matcher.values
	targetToMatch := target
	if !isCaseSensitive(matcher.matcher) {
		values = matcher.lowerValues
		targetToMatch = lowerTarget
	}
	for i, value := range values {
		if strings.Contains(targetToMatch, value) {
			matchedValue := matcher.values[i]
			return evidence(source, matcher.matcher, snippet(target, matchedValue), responseURL), true
		}
	}
	return Evidence{}, false
}

func matchPreparedRegex(source string, matcher compiledMatcher, target string, responseURL string) (Evidence, bool) {
	for _, re := range matcher.regexps {
		match := re.FindString(target)
		if match != "" {
			return evidence(source, matcher.matcher, truncate(match, 160), responseURL), true
		}
	}
	return Evidence{}, false
}

func matchPreparedHeaderContains(headers http.Header, matcher compiledMatcher, responseURL string) (Evidence, bool) {
	for key, headerValues := range headers {
		if matcher.matcher.Key != "" && !strings.EqualFold(key, matcher.matcher.Key) {
			continue
		}
		if matcher.matcher.Key != "" && len(matcher.values) == 0 {
			return evidence("header", matcher.matcher, key, responseURL), true
		}
		for _, headerValue := range headerValues {
			target := key + ": " + headerValue
			if ev, ok := matchPreparedText("header", matcher, target, strings.ToLower(target), responseURL); ok {
				return ev, true
			}
		}
		if matcher.matcher.Key == "" {
			if ev, ok := matchPreparedText("header", matcher, key, strings.ToLower(key), responseURL); ok {
				return ev, true
			}
		}
	}
	return Evidence{}, false
}

func matchPreparedHeaderRegex(headers http.Header, matcher compiledMatcher, responseURL string) (Evidence, bool) {
	for key, headerValues := range headers {
		if matcher.matcher.Key != "" && !strings.EqualFold(key, matcher.matcher.Key) {
			continue
		}
		for _, headerValue := range headerValues {
			if ev, ok := matchPreparedRegex("header", matcher, key+": "+headerValue, responseURL); ok {
				return ev, true
			}
		}
	}
	return Evidence{}, false
}

func matchPreparedJSONKey(response *preparedResponse, matcher compiledMatcher) (Evidence, bool) {
	data, ok := response.json()
	if !ok {
		return Evidence{}, false
	}
	for _, key := range matcher.values {
		if jsonKeyExists(data, key) {
			return evidence("json", matcher.matcher, key, response.response.URL), true
		}
	}
	return Evidence{}, false
}

func matchPreparedJSONPath(response *preparedResponse, matcher compiledMatcher) (Evidence, bool) {
	data, ok := response.json()
	if !ok {
		return Evidence{}, false
	}
	path := matcher.matcher.Key
	values := matcher.values
	if path == "" && len(values) > 0 {
		path = values[0]
		values = values[1:]
	}
	if path == "" || len(values) == 0 {
		return Evidence{}, false
	}
	actual, ok := jsonPathValue(data, strings.Split(path, "."))
	if !ok {
		return Evidence{}, false
	}
	actualText := fmt.Sprint(actual)
	for _, expected := range values {
		if actualText == expected {
			return evidence("json", matcher.matcher, path+"="+actualText, response.response.URL), true
		}
	}
	return Evidence{}, false
}

func (response *preparedResponse) json() (interface{}, bool) {
	if response.jsonParsed {
		return response.jsonData, response.jsonOK
	}
	response.jsonParsed = true
	if err := json.Unmarshal(response.response.Body, &response.jsonData); err != nil {
		return nil, false
	}
	response.jsonOK = true
	return response.jsonData, true
}

func extractCompiledVersion(responses []*preparedResponse, rule compiledRule) string {
	for _, extractor := range rule.extractors {
		for _, response := range responses {
			if value := applyCompiledExtractor(response, extractor); value != "" {
				return value
			}
		}
	}
	return ""
}

func applyCompiledExtractor(response *preparedResponse, extractor compiledExtractor) string {
	source := extractorPreparedSource(response, extractor.extractor)
	if source == "" {
		return ""
	}
	matches := extractor.regex.FindStringSubmatch(source)
	if len(matches) == 0 {
		return ""
	}
	group := extractor.extractor.Group
	if group <= 0 {
		group = 1
	}
	if group >= len(matches) {
		return truncate(matches[0], 80)
	}
	return truncate(matches[group], 80)
}

func extractorPreparedSource(response *preparedResponse, extractor Extractor) string {
	switch strings.ToLower(strings.TrimSpace(extractor.Type)) {
	case "body", "body.regex":
		return response.body
	case "title", "title.regex":
		return response.title
	case "header", "header.regex":
		if extractor.Key != "" {
			return response.response.Header.Get(extractor.Key)
		}
		var builder strings.Builder
		for key, values := range response.response.Header {
			for _, value := range values {
				builder.WriteString(key)
				builder.WriteString(": ")
				builder.WriteString(value)
				builder.WriteString("\n")
			}
		}
		return builder.String()
	case "server", "server.banner", "server.banner.regex":
		return response.server
	case "tls.cert.subject":
		return response.tlsSubject
	case "tls.cert.issuer":
		return response.tlsIssuer
	case "tls.cert.dns":
		return response.tlsDNS
	case "tls.alpn":
		return response.tlsALPN
	default:
		return ""
	}
}

func findPreparedEvidenceResponse(responses []*preparedResponse, responseURL string) Response {
	for _, response := range responses {
		if response.response.URL == responseURL {
			return response.response
		}
	}
	return responses[0].response
}

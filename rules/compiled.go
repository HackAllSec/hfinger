package rules

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash/maphash"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/PuerkitoBio/goquery"
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
	contains    *containsAutomaton
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

	header preparedHeaderIndex

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
	tlsVersion      string
	lowerTLSVersion string
	tlsCipher       string
	lowerTLSCipher  string
	tlsJA3S         string

	faviconMMH3      string
	faviconMD5       string
	faviconSHA1      string
	faviconSHA256    string
	scriptHashes     []ResourceHash
	stylesheetHashes []ResourceHash

	dnsCNAME            string
	lowerDNSCNAME       string
	dnsNameservers      string
	lowerDNSNameservers string
	dnsTXT              string
	lowerDNSTXT         string
	dnsIPs              string
	lowerDNSIPs         string

	httpVersion         string
	lowerHTTPVersion    string
	allowedMethods      string
	lowerAllowedMethods string
	compression         string
	lowerCompression    string
	altSvc              string
	lowerAltSvc         string
	cacheHeaders        string
	lowerCacheHeaders   string

	jsonParsed bool
	jsonOK     bool
	jsonData   interface{}
}

type preparedResponses struct {
	items     []*preparedResponse
	byProbeID map[string][]*preparedResponse
	byPath    map[string][]*preparedResponse
}

type preparedHeaderIndex struct {
	keys            []string
	lowerKeys       []string
	lines           []string
	lowerLines      []string
	linesByKey      map[string][]string
	lowerLinesByKey map[string][]string
}

var compiledRuleSetCache = struct {
	sync.RWMutex
	byContent map[string][]compiledRule
}{
	byContent: make(map[string][]compiledRule),
}

var compiledRuleSetCacheSeed = maphash.MakeSeed()

const compiledRuleSetCacheLimit = 32

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
	case "body.contains", "header.contains", "title.contains", "cookie.contains", "redirect.to", "server.banner.contains",
		"tls.cert.subject.contains", "tls.cert.issuer.contains", "tls.cert.dns.contains", "tls.alpn.contains",
		"tls.version.contains", "tls.cipher.contains", "http.version.contains", "http.method.allowed",
		"response.compression.contains", "response.cache.contains", "http.alt_svc.contains",
		"dns.cname.contains", "dns.ns.contains", "dns.txt.contains", "dns.ip.contains":
		automatonValues := cm.values
		if !isCaseSensitive(matcher) {
			automatonValues = cm.lowerValues
		}
		if len(automatonValues) > 1 && !containsEmptyString(automatonValues) {
			cm.contains = newContainsAutomaton(automatonValues)
		}
	case "body.regex", "header.regex", "title.regex", "server.banner.regex":
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

type containsAutomaton struct {
	nodes []containsNode
}

type containsNode struct {
	edges   []containsEdge
	fail    int
	outputs []int
}

type containsEdge struct {
	ch   byte
	next int
}

func newContainsAutomaton(patterns []string) *containsAutomaton {
	automaton := &containsAutomaton{nodes: []containsNode{{}}}
	nonEmpty := 0
	for index, pattern := range patterns {
		if pattern == "" {
			continue
		}
		nonEmpty++
		state := 0
		for i := 0; i < len(pattern); i++ {
			ch := pattern[i]
			next, ok := automaton.nextState(state, ch)
			if !ok {
				next = len(automaton.nodes)
				automaton.nodes[state].edges = append(automaton.nodes[state].edges, containsEdge{ch: ch, next: next})
				automaton.nodes = append(automaton.nodes, containsNode{})
			}
			state = next
		}
		automaton.nodes[state].outputs = append(automaton.nodes[state].outputs, index)
	}
	if nonEmpty == 0 {
		return nil
	}

	queue := make([]int, 0, len(automaton.nodes))
	for _, edge := range automaton.nodes[0].edges {
		queue = append(queue, edge.next)
	}
	for head := 0; head < len(queue); head++ {
		state := queue[head]
		for _, edge := range automaton.nodes[state].edges {
			ch := edge.ch
			child := edge.next
			fail := automaton.nodes[state].fail
			for fail != 0 {
				if next, ok := automaton.nextState(fail, ch); ok {
					fail = next
					break
				}
				fail = automaton.nodes[fail].fail
			}
			if fail == 0 {
				if next, ok := automaton.nextState(0, ch); ok && next != child {
					fail = next
				}
			}
			automaton.nodes[child].fail = fail
			if len(automaton.nodes[fail].outputs) > 0 {
				automaton.nodes[child].outputs = append(automaton.nodes[child].outputs, automaton.nodes[fail].outputs...)
			}
			queue = append(queue, child)
		}
	}
	return automaton
}

func containsEmptyString(values []string) bool {
	for _, value := range values {
		if value == "" {
			return true
		}
	}
	return false
}

func (automaton *containsAutomaton) nextState(state int, ch byte) (int, bool) {
	for _, edge := range automaton.nodes[state].edges {
		if edge.ch == ch {
			return edge.next, true
		}
	}
	return 0, false
}

func (automaton *containsAutomaton) matchIndex(target string) (int, bool) {
	if automaton == nil {
		return 0, false
	}
	state := 0
	best := -1
	for i := 0; i < len(target); i++ {
		ch := target[i]
		for state != 0 {
			if _, ok := automaton.nextState(state, ch); ok {
				break
			}
			state = automaton.nodes[state].fail
		}
		if next, ok := automaton.nextState(state, ch); ok {
			state = next
		}
		for _, patternIndex := range automaton.nodes[state].outputs {
			if best == -1 || patternIndex < best {
				best = patternIndex
				if best == 0 {
					return best, true
				}
			}
		}
	}
	return best, best >= 0
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

func compiledRulesFor(ruleSet []Rule) []compiledRule {
	if len(ruleSet) == 0 {
		return nil
	}
	key := ruleSetCacheKey(ruleSet)
	compiledRuleSetCache.RLock()
	compiled, ok := compiledRuleSetCache.byContent[key]
	compiledRuleSetCache.RUnlock()
	if ok {
		return compiled
	}

	compiled = compileRules(ruleSet)
	compiledRuleSetCache.Lock()
	if cached, ok := compiledRuleSetCache.byContent[key]; ok {
		compiledRuleSetCache.Unlock()
		return cached
	}
	if len(compiledRuleSetCache.byContent) >= compiledRuleSetCacheLimit {
		compiledRuleSetCache.byContent = make(map[string][]compiledRule)
	}
	compiledRuleSetCache.byContent[key] = compiled
	compiledRuleSetCache.Unlock()
	return compiled
}

func ruleSetCacheKey(ruleSet []Rule) string {
	var hash maphash.Hash
	hash.SetSeed(compiledRuleSetCacheSeed)
	writeCacheInt(&hash, len(ruleSet))
	for _, rule := range ruleSet {
		writeCachePart(&hash, rule.ID)
		writeCachePart(&hash, rule.Name)
		writeCachePart(&hash, rule.Category)
		writeCachePart(&hash, rule.Match.Strategy)
		writeCacheInt(&hash, rule.Match.Threshold)
		for _, matcher := range rule.Negative {
			writeMatcherCacheKey(&hash, matcher)
		}
		if len(rule.Match.Probes) > 0 {
			for _, probe := range rule.Match.Probes {
				writeProbeCacheKey(&hash, probe)
			}
		} else {
			writeCachePart(&hash, "default")
			for _, matcher := range rule.Match.Matchers {
				writeMatcherCacheKey(&hash, matcher)
			}
		}
		for _, extractor := range rule.Extract {
			writeCachePart(&hash, extractor.Name)
			writeCachePart(&hash, extractor.Type)
			writeCachePart(&hash, extractor.Key)
			writeCachePart(&hash, extractor.Regex)
			writeCacheInt(&hash, extractor.Group)
		}
	}
	return strconv.FormatUint(hash.Sum64(), 16)
}

func writeProbeCacheKey(cacheHash *maphash.Hash, probe Probe) {
	writeCachePart(cacheHash, probe.ID)
	writeCachePart(cacheHash, probe.Request.Method)
	writeCachePart(cacheHash, probe.Request.Path)
	writeCachePart(cacheHash, probe.Request.Body)
	headerKeys := make([]string, 0, len(probe.Request.Headers))
	for key := range probe.Request.Headers {
		headerKeys = append(headerKeys, key)
	}
	sort.Strings(headerKeys)
	for _, key := range headerKeys {
		writeCachePart(cacheHash, key)
		writeCachePart(cacheHash, probe.Request.Headers[key])
	}
	for _, matcher := range probe.Matchers {
		writeMatcherCacheKey(cacheHash, matcher)
	}
}

func writeMatcherCacheKey(cacheHash *maphash.Hash, matcher Matcher) {
	writeCachePart(cacheHash, matcher.Type)
	writeCachePart(cacheHash, matcher.Key)
	writeMatcherValueCacheKey(cacheHash, matcher.Value)
	for _, value := range matcher.Values {
		writeCachePart(cacheHash, value)
	}
	writeCacheInt(cacheHash, matcher.Weight)
	if matcher.CaseSensitive == nil {
		writeCachePart(cacheHash, "case:nil")
	} else {
		writeCachePart(cacheHash, strconv.FormatBool(*matcher.CaseSensitive))
	}
}

func writeMatcherValueCacheKey(cacheHash *maphash.Hash, value interface{}) {
	switch typed := value.(type) {
	case nil:
		writeCachePart(cacheHash, "nil")
	case string:
		writeCachePart(cacheHash, typed)
	case int:
		writeCacheInt(cacheHash, typed)
	case int64:
		writeCacheInt64(cacheHash, typed)
	case float64:
		writeCacheInt64(cacheHash, int64(typed))
	case []interface{}:
		writeCacheInt(cacheHash, len(typed))
		for _, item := range typed {
			writeMatcherValueCacheKey(cacheHash, item)
		}
	default:
		writeCachePart(cacheHash, fmt.Sprint(typed))
	}
}

func writeCachePart(cacheHash *maphash.Hash, value string) {
	writeCacheInt(cacheHash, len(value))
	cacheHash.WriteString(value)
	_, _ = cacheHash.Write([]byte{0})
}

func writeCacheInt(cacheHash *maphash.Hash, value int) {
	writeCacheInt64(cacheHash, int64(value))
}

func writeCacheInt64(cacheHash *maphash.Hash, value int64) {
	var buffer [8]byte
	binary.LittleEndian.PutUint64(buffer[:], uint64(value))
	_, _ = cacheHash.Write(buffer[:])
}

func prepareResponses(responses []Response) []*preparedResponse {
	return prepareResponseSet(responses).items
}

func prepareResponseSet(responses []Response) preparedResponses {
	prepared := preparedResponses{
		items:     make([]*preparedResponse, 0, len(responses)),
		byProbeID: make(map[string][]*preparedResponse),
		byPath:    make(map[string][]*preparedResponse),
	}
	for _, response := range responses {
		body := string(response.Body)
		tlsDNS := strings.Join(response.TLS.DNSNames, ",")
		faviconMMH3 := ""
		faviconMD5 := ""
		faviconSHA1 := ""
		faviconSHA256 := ""
		if len(response.Favicon) > 0 {
			// 同一响应只计算一次 favicon 摘要，避免多个 matcher 重复消耗 CPU。
			hash := int32(murmur3.SeedSum32(0, response.Favicon))
			faviconMMH3 = strconv.FormatInt(int64(hash), 10)
			faviconMD5, faviconSHA1, faviconSHA256 = contentHashes(response.Favicon)
		}
		allowedMethods := strings.Join(response.Behavior.Allowed, ",")
		item := &preparedResponse{
			response: response,

			body:      body,
			lowerBody: strings.ToLower(body),

			header: buildPreparedHeaderIndex(response.Header),

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
			tlsVersion:      response.TLS.Version,
			lowerTLSVersion: strings.ToLower(response.TLS.Version),
			tlsCipher:       response.TLS.CipherSuite,
			lowerTLSCipher:  strings.ToLower(response.TLS.CipherSuite),
			tlsJA3S:         response.TLS.JA3S,

			faviconMMH3:         faviconMMH3,
			faviconMD5:          faviconMD5,
			faviconSHA1:         faviconSHA1,
			faviconSHA256:       faviconSHA256,
			scriptHashes:        response.Scripts,
			stylesheetHashes:    response.Stylesheets,
			dnsCNAME:            response.DNS.CNAME,
			lowerDNSCNAME:       strings.ToLower(response.DNS.CNAME),
			dnsNameservers:      strings.Join(response.DNS.Nameservers, ","),
			lowerDNSNameservers: strings.ToLower(strings.Join(response.DNS.Nameservers, ",")),
			dnsTXT:              strings.Join(response.DNS.TXT, ","),
			lowerDNSTXT:         strings.ToLower(strings.Join(response.DNS.TXT, ",")),
			dnsIPs:              strings.Join(response.DNS.IPs, ","),
			lowerDNSIPs:         strings.ToLower(strings.Join(response.DNS.IPs, ",")),
			httpVersion:         response.Behavior.HTTPVersion,
			lowerHTTPVersion:    strings.ToLower(response.Behavior.HTTPVersion),
			allowedMethods:      allowedMethods,
			lowerAllowedMethods: strings.ToLower(allowedMethods),
			compression:         response.Behavior.Compression,
			lowerCompression:    strings.ToLower(response.Behavior.Compression),
			altSvc:              response.Behavior.AltSvc,
			lowerAltSvc:         strings.ToLower(response.Behavior.AltSvc),
			cacheHeaders:        response.Behavior.Cache,
			lowerCacheHeaders:   strings.ToLower(response.Behavior.Cache),
		}
		prepared.items = append(prepared.items, item)
		if response.ProbeID != "" {
			prepared.byProbeID[response.ProbeID] = append(prepared.byProbeID[response.ProbeID], item)
		}
		if response.Path != "" {
			prepared.byPath[response.Path] = append(prepared.byPath[response.Path], item)
		}
	}
	return prepared
}

func buildPreparedHeaderIndex(headers http.Header) preparedHeaderIndex {
	index := preparedHeaderIndex{
		linesByKey:      make(map[string][]string, len(headers)),
		lowerLinesByKey: make(map[string][]string, len(headers)),
	}
	for key, values := range headers {
		lowerKey := strings.ToLower(key)
		index.keys = append(index.keys, key)
		index.lowerKeys = append(index.lowerKeys, lowerKey)
		if len(values) == 0 {
			continue
		}
		for _, value := range values {
			line := key + ": " + value
			lowerLine := strings.ToLower(line)
			index.lines = append(index.lines, line)
			index.lowerLines = append(index.lowerLines, lowerLine)
			index.linesByKey[lowerKey] = append(index.linesByKey[lowerKey], line)
			index.lowerLinesByKey[lowerKey] = append(index.lowerLinesByKey[lowerKey], lowerLine)
		}
	}
	return index
}

func matchCompiledRules(responses []Response, compiled []compiledRule) []MatchResult {
	prepared := prepareResponseSet(responses)
	results := make([]MatchResult, 0)
	for _, rule := range compiled {
		result := matchCompiledRule(prepared, rule)
		if result.Matched {
			results = append(results, result)
		}
	}
	return results
}

func matchCompiledRule(responses preparedResponses, rule compiledRule) MatchResult {
	result := MatchResult{Rule: rule.rule}
	if len(responses.items) == 0 {
		return result
	}

	for _, negative := range rule.negative {
		if evidence, ok := matchAnyPreparedResponse(responses.items, negative); ok {
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
				result.Response = findPreparedEvidenceResponse(responses.items, evidence.ResponseURL)
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
		result.Version = extractCompiledVersion(responses.items, rule)
	}
	return result
}

func filterPreparedResponsesForProbe(responses preparedResponses, probe Probe) []*preparedResponse {
	path := probe.Request.Path
	if path == "" {
		return responses.items
	}
	pathCandidates := responses.byPath[path]
	if probe.ID == "" {
		return pathCandidates
	}
	probeCandidates := responses.byProbeID[probe.ID]
	if len(probeCandidates) == 0 {
		return pathCandidates
	}
	if len(pathCandidates) == 0 {
		return probeCandidates
	}

	candidates := make([]*preparedResponse, 0, len(probeCandidates)+len(pathCandidates))
	seen := make(map[*preparedResponse]struct{}, len(probeCandidates)+len(pathCandidates))
	candidates = appendPreparedCandidates(candidates, seen, probeCandidates)
	return appendPreparedCandidates(candidates, seen, pathCandidates)
}

func appendPreparedCandidates(dst []*preparedResponse, seen map[*preparedResponse]struct{}, src []*preparedResponse) []*preparedResponse {
	for _, response := range src {
		if _, ok := seen[response]; ok {
			continue
		}
		seen[response] = struct{}{}
		dst = append(dst, response)
	}
	return dst
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
		return matchPreparedHeaderContains(response.header, matcher, response.response.URL)
	case "header.regex":
		return matchPreparedHeaderRegex(response.header, matcher, response.response.URL)
	case "title.contains":
		return matchPreparedText("title", matcher, response.title, response.lowerTitle, response.response.URL)
	case "title.regex":
		return matchPreparedRegex("title", matcher, response.title, response.response.URL)
	case "cookie.contains":
		cookieMatcher := matcher
		cookieMatcher.matcher.Key = "Set-Cookie"
		return matchPreparedHeaderContains(response.header, cookieMatcher, response.response.URL)
	case "status.eq", "status.in":
		if _, ok := matcher.statusCodes[response.response.StatusCode]; ok {
			return evidence("status", matcher.matcher, strconv.Itoa(response.response.StatusCode), response.response.URL), true
		}
	case "favicon.hash":
		return matchPreparedExact("favicon", matcher, response.faviconMMH3, response.response.URL)
	case "favicon.hash.md5":
		return matchPreparedExact("favicon.md5", matcher, response.faviconMD5, response.response.URL)
	case "favicon.hash.sha1":
		return matchPreparedExact("favicon.sha1", matcher, response.faviconSHA1, response.response.URL)
	case "favicon.hash.sha256":
		return matchPreparedExact("favicon.sha256", matcher, response.faviconSHA256, response.response.URL)
	case "redirect.to":
		return matchPreparedText("redirect", matcher, response.redirect, response.lowerRedirect, response.response.URL)
	case "script.src.contains":
		return matchPreparedRegex("script.src", matcher, response.body, response.response.URL)
	case "script.hash.md5":
		return matchPreparedResourceHash("script.md5", matcher, response.scriptHashes, func(item ResourceHash) string { return item.MD5 }, response.response.URL)
	case "script.hash.sha1":
		return matchPreparedResourceHash("script.sha1", matcher, response.scriptHashes, func(item ResourceHash) string { return item.SHA1 }, response.response.URL)
	case "script.hash.sha256":
		return matchPreparedResourceHash("script.sha256", matcher, response.scriptHashes, func(item ResourceHash) string { return item.SHA256 }, response.response.URL)
	case "stylesheet.hash.md5":
		return matchPreparedResourceHash("stylesheet.md5", matcher, response.stylesheetHashes, func(item ResourceHash) string { return item.MD5 }, response.response.URL)
	case "stylesheet.hash.sha1":
		return matchPreparedResourceHash("stylesheet.sha1", matcher, response.stylesheetHashes, func(item ResourceHash) string { return item.SHA1 }, response.response.URL)
	case "stylesheet.hash.sha256":
		return matchPreparedResourceHash("stylesheet.sha256", matcher, response.stylesheetHashes, func(item ResourceHash) string { return item.SHA256 }, response.response.URL)
	case "html.meta.contains":
		return matchPreparedRegex("html.meta", matcher, response.body, response.response.URL)
	case "html.selector.exists":
		return matchPreparedHTMLSelector(response, matcher)
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
	case "tls.version.contains":
		return matchPreparedText("tls.version", matcher, response.tlsVersion, response.lowerTLSVersion, response.response.URL)
	case "tls.cipher.contains":
		return matchPreparedText("tls.cipher", matcher, response.tlsCipher, response.lowerTLSCipher, response.response.URL)
	case "tls.ja3s.hash":
		return matchPreparedExact("tls.ja3s", matcher, response.tlsJA3S, response.response.URL)
	case "dns.cname.contains":
		return matchPreparedText("dns.cname", matcher, response.dnsCNAME, response.lowerDNSCNAME, response.response.URL)
	case "dns.ns.contains":
		return matchPreparedText("dns.ns", matcher, response.dnsNameservers, response.lowerDNSNameservers, response.response.URL)
	case "dns.txt.contains":
		return matchPreparedText("dns.txt", matcher, response.dnsTXT, response.lowerDNSTXT, response.response.URL)
	case "dns.ip.contains":
		return matchPreparedText("dns.ip", matcher, response.dnsIPs, response.lowerDNSIPs, response.response.URL)
	case "http.version.contains":
		return matchPreparedText("http.version", matcher, response.httpVersion, response.lowerHTTPVersion, response.response.URL)
	case "http.alt_svc.contains":
		return matchPreparedText("http.alt_svc", matcher, response.altSvc, response.lowerAltSvc, response.response.URL)
	case "http.method.allowed":
		return matchPreparedText("http.allow", matcher, response.allowedMethods, response.lowerAllowedMethods, response.response.URL)
	case "response.compression.contains":
		return matchPreparedText("response.compression", matcher, response.compression, response.lowerCompression, response.response.URL)
	case "response.cache.contains":
		return matchPreparedText("response.cache", matcher, response.cacheHeaders, response.lowerCacheHeaders, response.response.URL)
	case "response.etag.exists":
		if value := headerValue(response.response.Header, "ETag"); value != "" {
			return evidence("response.etag", matcher.matcher, value, response.response.URL), true
		}
	case "response.accept_ranges.exists":
		if value := headerValue(response.response.Header, "Accept-Ranges"); value != "" {
			return evidence("response.accept_ranges", matcher.matcher, value, response.response.URL), true
		}
	}
	return Evidence{}, false
}

func matchPreparedHTMLSelector(response *preparedResponse, matcher compiledMatcher) (Evidence, bool) {
	if strings.TrimSpace(response.body) == "" {
		return Evidence{}, false
	}
	document, err := goquery.NewDocumentFromReader(bytes.NewBufferString(response.body))
	if err != nil {
		return Evidence{}, false
	}
	for _, selector := range matcher.values {
		selector = strings.TrimSpace(selector)
		if selector == "" {
			continue
		}
		if document.Find(selector).Length() > 0 {
			return evidence("html.selector", matcher.matcher, selector, response.response.URL), true
		}
	}
	return Evidence{}, false
}

func headerValue(headers http.Header, key string) string {
	if value := headers.Get(key); value != "" {
		return value
	}
	for headerKey, values := range headers {
		if strings.EqualFold(headerKey, key) && len(values) > 0 {
			return values[0]
		}
	}
	return ""
}

func contentHashes(data []byte) (string, string, string) {
	md5Sum := md5.Sum(data)
	sha1Sum := sha1.Sum(data)
	sha256Sum := sha256.Sum256(data)
	return hex.EncodeToString(md5Sum[:]), hex.EncodeToString(sha1Sum[:]), hex.EncodeToString(sha256Sum[:])
}

func matchPreparedExact(source string, matcher compiledMatcher, actual string, responseURL string) (Evidence, bool) {
	if actual == "" {
		return Evidence{}, false
	}
	for _, expected := range matcher.values {
		if strings.EqualFold(actual, expected) {
			return evidence(source, matcher.matcher, actual, responseURL), true
		}
	}
	return Evidence{}, false
}

func matchPreparedResourceHash(source string, matcher compiledMatcher, hashes []ResourceHash, value func(ResourceHash) string, responseURL string) (Evidence, bool) {
	for _, item := range hashes {
		actual := value(item)
		for _, expected := range matcher.values {
			if actual != "" && strings.EqualFold(actual, expected) {
				matched := actual
				if item.URL != "" {
					matched = item.URL + " " + actual
				}
				return evidence(source, matcher.matcher, matched, responseURL), true
			}
		}
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
	if matcher.contains != nil {
		if matchIndex, ok := matcher.contains.matchIndex(targetToMatch); ok && matchIndex < len(values) {
			matchedValue := matcher.values[matchIndex]
			return evidence(source, matcher.matcher, snippet(target, matchedValue), responseURL), true
		}
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

func matchPreparedHeaderContains(headers preparedHeaderIndex, matcher compiledMatcher, responseURL string) (Evidence, bool) {
	if matcher.matcher.Key != "" {
		lowerKey := strings.ToLower(matcher.matcher.Key)
		if len(matcher.values) == 0 {
			for i, key := range headers.keys {
				if headers.lowerKeys[i] == lowerKey {
					return evidence("header", matcher.matcher, key, responseURL), true
				}
			}
			return Evidence{}, false
		}
		return matchPreparedTextList("header", matcher, headers.linesByKey[lowerKey], headers.lowerLinesByKey[lowerKey], responseURL)
	}

	if ev, ok := matchPreparedTextList("header", matcher, headers.lines, headers.lowerLines, responseURL); ok {
		return ev, true
	}
	for i, key := range headers.keys {
		if ev, ok := matchPreparedText("header", matcher, key, headers.lowerKeys[i], responseURL); ok {
			return ev, true
		}
	}
	return Evidence{}, false
}

func matchPreparedTextList(source string, matcher compiledMatcher, targets []string, lowerTargets []string, responseURL string) (Evidence, bool) {
	for i, target := range targets {
		lowerTarget := ""
		if i < len(lowerTargets) {
			lowerTarget = lowerTargets[i]
		}
		if ev, ok := matchPreparedText(source, matcher, target, lowerTarget, responseURL); ok {
			return ev, true
		}
	}
	return Evidence{}, false
}

func matchPreparedHeaderRegex(headers preparedHeaderIndex, matcher compiledMatcher, responseURL string) (Evidence, bool) {
	lines := headers.lines
	if matcher.matcher.Key != "" {
		lines = headers.linesByKey[strings.ToLower(matcher.matcher.Key)]
	}
	for _, line := range lines {
		if ev, ok := matchPreparedRegex("header", matcher, line, responseURL); ok {
			return ev, true
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

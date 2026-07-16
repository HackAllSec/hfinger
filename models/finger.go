package models

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"

	"hfinger/config"
	"hfinger/logger"
	"hfinger/output"
	"hfinger/rules"
	"hfinger/utils"
)

var (
	workerCount  int
	maxRedirects int
	outputLock   sync.Mutex // 全局锁保护output操作
	scriptSrcRe  = regexp.MustCompile(`(?is)<script[^>]+src=["']([^"']+)["']`)
)

func process(url string, probeID string, request rules.Request, responsesChannel chan<- rules.Response, mu *sync.Mutex, wg *sync.WaitGroup, errOccurred *bool, saveResponse func(int, string, string)) {
	defer wg.Done()

	currentURL := url
	redirectCount := 0

	for redirectCount <= maxRedirects {
		mu.Lock()
		if *errOccurred {
			mu.Unlock()
			return
		}
		mu.Unlock()

		resp, err := utils.Do(request.Method, currentURL, []byte(request.Body), request.Headers)
		if err != nil {
			mu.Lock()
			if !*errOccurred {
				logger.PrintByLevel(err, currentURL)
				*errOccurred = logger.ShouldTerminate(err)
			}
			mu.Unlock()
			return
		}

		// 读取响应后立即关闭body
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			logger.PrintByLevel(err, currentURL)
			return
		}

		// 检查是否需要重定向
		redirectURL := utils.ExtractRedirectURL(resp, body)
		if redirectURL != "" && redirectCount < maxRedirects {
			newURL, err := utils.ResolveRelativeURL(currentURL, redirectURL)
			if err != nil {
				// 记录错误但继续处理当前响应
				logger.Warn("Invalid redirect URL: %s", redirectURL)
			} else {
				// 更新当前URL并继续重定向循环
				logger.Hint("Redirecting: %s ➨ %s", currentURL, newURL)
				currentURL = newURL
				redirectCount++
				continue // 跳过当前响应的处理，重新请求
			}
		}

		statusCode := resp.StatusCode
		server := resp.Header.Get("Server")
		if server == "" {
			server = "None"
		}
		title := utils.FetchTitle(body)
		if title == "" {
			title = "None"
		}

		faviconpath := utils.FetchFavicon(body)
		var faviconbody []byte
		if faviconpath != "" && resp.StatusCode == http.StatusOK {
			baseurl, _ := utils.GetBaseURL(currentURL)
			faviconurl := faviconpath
			if !strings.HasPrefix(faviconpath, "http://") && !strings.HasPrefix(faviconpath, "https://") {
				if faviconpath[0] == '/' {
					faviconurl = baseurl + faviconpath
				} else {
					faviconurl = baseurl + "/" + faviconpath
				}
			}

			favicon, err := utils.Get(faviconurl, nil)
			if err == nil && favicon.StatusCode == http.StatusOK {
				defer favicon.Body.Close()
				faviconbody, err = io.ReadAll(favicon.Body)
				if err != nil {
					logger.PrintByLevel(err, currentURL)
				}
			}
		}

		// 保存第一次请求结果，无匹配结果时输出
		if saveResponse != nil {
			saveResponse(statusCode, server, title)
		}

		responsesChannel <- rules.Response{
			ProbeID:    probeID,
			URL:        currentURL,
			Path:       rules.PathFromURL(currentURL),
			StatusCode: statusCode,
			Server:     server,
			Title:      title,
			Header:     resp.Header,
			Body:       body,
			Favicon:    faviconbody,
			Scripts:    scriptHashes(currentURL, body),
			TLS:        tlsInfo(resp),
			Behavior:   behaviorInfo(resp),
		}
		break // 退出循环
	}
}

func ProcessURL(url string) {
	var wg sync.WaitGroup
	var mu sync.Mutex
	var errOccurred bool
	var matchedCMS sync.Map
	responsesChannel := make(chan rules.Response, workerCount+len(rules.ActiveHTTPProbes())+3)

	var lastResp config.LastResponse
	var firstRespOnce sync.Once

	saveFirstResponse := func(code int, server string, title string) {
		firstRespOnce.Do(func() {
			lastResp = config.LastResponse{
				StatusCode: code,
				Server:     server,
				Title:      title,
			}
			if lastResp.Server == "" {
				lastResp.Server = "None"
			}
			if lastResp.Title == "" {
				lastResp.Title = "None"
			}
		})
	}

	wg.Add(4)
	go process(url, "default", rules.Request{Method: "GET"}, responsesChannel, &mu, &wg, &errOccurred, saveFirstResponse)
	go process(url, "remember-me", rules.Request{Method: "GET", Headers: map[string]string{"Cookie": "rememberMe=1"}}, responsesChannel, &mu, &wg, &errOccurred, nil)
	go process(url, "options", rules.Request{Method: "OPTIONS"}, responsesChannel, &mu, &wg, &errOccurred, nil)

	suffix := fmt.Sprintf("/%x", rand.Int())
	if url[len(url)-1] == '/' {
		suffix = fmt.Sprintf("%x", rand.Int())
	}
	newUrl := url + suffix
	go process(newUrl, "error-page", rules.Request{Method: "GET"}, responsesChannel, &mu, &wg, &errOccurred, nil)

	baseURL, baseErr := utils.GetBaseURL(url)
	if baseErr == nil {
		for _, probe := range rules.ActiveHTTPProbes() {
			probeURL := baseURL + probe.Request.Path
			wg.Add(1)
			go process(probeURL, probe.ID, probe.Request, responsesChannel, &mu, &wg, &errOccurred, nil)
		}
	}

	wg.Wait()

	close(responsesChannel)

	var responses []rules.Response
	for response := range responsesChannel {
		responses = append(responses, response)
	}
	var results []config.Result
	matches := rules.MatchRules(responses, rules.ActiveRules())
	if honeypot := rules.AssessHoneypot(matches, responses); honeypot.Matched {
		matches = append(matches, honeypot)
	}
	for _, match := range matches {
		cms := match.Rule.Name
		if _, loaded := matchedCMS.LoadOrStore(cms, true); loaded {
			continue
		}
		response := preferredResponse(responses, match.Response)
		result := config.Result{
			URL:        response.URL,
			CMS:        cms,
			Category:   match.Rule.Category,
			Version:    match.Version,
			Server:     response.Server,
			StatusCode: response.StatusCode,
			Title:      response.Title,
			Confidence: match.Confidence,
			Evidence:   match.Evidence,
		}
		results = append(results, result)
		logger.Success("[%s] [%s] [%d] [%s] [%s] [Confidence %d%%]", result.URL, result.CMS, result.StatusCode, result.Server, result.Title, result.Confidence)
	}

	outputLock.Lock()
	defer outputLock.Unlock()
	for _, result := range results {
		output.AddResults(result)
	}

	mu.Lock()
	defer mu.Unlock()
	if countItems(&matchedCMS) == 0 && !errOccurred && lastResp.StatusCode != 0 {
		logger.Info("[%s] [Not Matched] [%d] [%s] [%s]",
			url,
			lastResp.StatusCode,
			lastResp.Server,
			lastResp.Title)
	}
}

func preferredResponse(responses []rules.Response, matched rules.Response) rules.Response {
	for _, response := range responses {
		if response.ProbeID == "default" {
			return response
		}
	}
	if matched.URL != "" {
		return matched
	}
	if len(responses) > 0 {
		return responses[0]
	}
	return rules.Response{}
}

func countItems(m *sync.Map) int {
	count := 0
	m.Range(func(_, _ interface{}) bool {
		count++
		return true
	})
	return count
}

func tlsInfo(resp *http.Response) rules.TLSInfo {
	if resp == nil || resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 {
		return rules.TLSInfo{}
	}
	cert := resp.TLS.PeerCertificates[0]
	version := tlsVersionName(resp.TLS.Version)
	cipher := tls.CipherSuiteName(resp.TLS.CipherSuite)
	return rules.TLSInfo{
		Subject:     cert.Subject.String(),
		Issuer:      cert.Issuer.String(),
		DNSNames:    cert.DNSNames,
		ALPN:        resp.TLS.NegotiatedProtocol,
		Version:     version,
		CipherSuite: cipher,
		JA3S:        serverTLSHash(version, cipher, resp.TLS.NegotiatedProtocol),
	}
}

func behaviorInfo(resp *http.Response) rules.BehaviorInfo {
	if resp == nil {
		return rules.BehaviorInfo{}
	}
	return rules.BehaviorInfo{
		HTTPVersion: resp.Proto,
		Compression: resp.Header.Get("Content-Encoding"),
		Allowed:     splitHeaderList(resp.Header.Get("Allow")),
	}
}

func splitHeaderList(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	values := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			values = append(values, part)
		}
	}
	return values
}

func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS1.0"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS13:
		return "TLS1.3"
	default:
		return fmt.Sprintf("0x%04x", version)
	}
}

func serverTLSHash(version string, cipher string, alpn string) string {
	// Go 标准库的 http.Response.TLS 拿不到完整 ServerHello 扩展顺序。
	// 这里输出的是稳定的 JA3S 风格摘要，不能等同于标准 JA3S。
	sum := md5.Sum([]byte(version + "," + cipher + "," + alpn))
	return hex.EncodeToString(sum[:])
}

func scriptHashes(pageURL string, body []byte) []rules.ResourceHash {
	// JS Hash 用于识别强绑定版本的前端静态资源；限制数量避免主动扫描放大流量。
	matches := scriptSrcRe.FindAllSubmatch(body, 16)
	hashes := make([]rules.ResourceHash, 0, len(matches))
	for _, match := range matches {
		if len(match) < 2 {
			continue
		}
		scriptURL, ok := resolveResourceURL(pageURL, string(match[1]))
		if !ok {
			continue
		}
		data, ok := fetchHashableResource(scriptURL)
		if !ok {
			continue
		}
		md5Value, sha1Value, sha256Value := resourceHashes(data)
		hashes = append(hashes, rules.ResourceHash{
			URL:    scriptURL,
			MD5:    md5Value,
			SHA1:   sha1Value,
			SHA256: sha256Value,
		})
	}
	return hashes
}

func resolveResourceURL(pageURL string, rawResource string) (string, bool) {
	base, err := url.Parse(pageURL)
	if err != nil {
		return "", false
	}
	ref, err := url.Parse(strings.TrimSpace(rawResource))
	if err != nil {
		return "", false
	}
	resolved := base.ResolveReference(ref)
	if resolved.Scheme != "http" && resolved.Scheme != "https" {
		return "", false
	}
	return resolved.String(), true
}

func fetchHashableResource(resourceURL string) ([]byte, bool) {
	resp, err := utils.Get(resourceURL, nil)
	if err != nil || resp == nil {
		return nil, false
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, false
	}
	// JS Hash 只需要稳定内容摘要，限制读取大小避免大资源拖慢批量扫描。
	data, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024+1))
	if err != nil || len(data) > 2*1024*1024 {
		return nil, false
	}
	return data, true
}

func resourceHashes(data []byte) (string, string, string) {
	md5Sum := md5.Sum(data)
	sha1Sum := sha1.Sum(data)
	sha256Sum := sha256.Sum256(data)
	return hex.EncodeToString(md5Sum[:]), hex.EncodeToString(sha1Sum[:]), hex.EncodeToString(sha256Sum[:])
}

func ProcessFile(filePath string) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		logger.Error("Error: %v", err)
		return
	}

	fileContent := string(data)
	fileContent = strings.ReplaceAll(fileContent, "\r\n", "\n")

	urls := strings.Split(fileContent, "\n")

	var wg sync.WaitGroup
	var sem = make(chan struct{}, workerCount)

	for _, url := range urls {
		url = targetFromInputLine(url)
		if url == "" {
			continue
		}

		wg.Add(1)
		sem <- struct{}{}
		go func(u string) {
			defer wg.Done()
			defer func() { <-sem }()
			ProcessURL(u)
		}(url)
	}

	wg.Wait()
	close(sem)

	outputLock.Lock()
	defer outputLock.Unlock()
	if err := output.WriteOutputs(); err != nil {
		logger.Error("Error writing output: %s", err)
	}
}

func targetFromInputLine(line string) string {
	line = strings.TrimSpace(line)
	if line == "" {
		return ""
	}
	if !strings.HasPrefix(line, "{") {
		return line
	}

	var record map[string]interface{}
	if err := json.Unmarshal([]byte(line), &record); err != nil {
		return line
	}
	for _, key := range []string{"url", "input", "host"} {
		if value, ok := record[key].(string); ok && strings.TrimSpace(value) != "" {
			target := strings.TrimSpace(value)
			if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
				return target
			}
			if scheme, ok := record["scheme"].(string); ok && scheme != "" {
				return scheme + "://" + target
			}
			return target
		}
	}
	return ""
}

func SetThread(thread int) {
	workerCount = thread
}

func SetMaxRedirects(count int) {
	maxRedirects = count
}

func ShowFingerPrints() {
	logger.Hint("Total number of fingerprint rules: %d", rules.Count())
	logger.Hint("Total number of products, web frameworks, and CMS: %d", rules.UniqueProductCount())
}

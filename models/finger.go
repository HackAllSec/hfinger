package models

import (
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
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
)

func process(url string, probeID string, headers map[string]string, responsesChannel chan<- rules.Response, mu *sync.Mutex, wg *sync.WaitGroup, errOccurred *bool, saveResponse func(int, string, string)) {
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

		resp, err := utils.Get(currentURL, headers)
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
			TLS:        tlsInfo(resp),
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

	wg.Add(3)
	go process(url, "default", nil, responsesChannel, &mu, &wg, &errOccurred, saveFirstResponse)
	go process(url, "remember-me", map[string]string{"Cookie": "rememberMe=1"}, responsesChannel, &mu, &wg, &errOccurred, nil)

	suffix := fmt.Sprintf("/%x", rand.Int())
	if url[len(url)-1] == '/' {
		suffix = fmt.Sprintf("%x", rand.Int())
	}
	newUrl := url + suffix
	go process(newUrl, "error-page", nil, responsesChannel, &mu, &wg, &errOccurred, nil)

	baseURL, baseErr := utils.GetBaseURL(url)
	if baseErr == nil {
		for _, probe := range rules.ActiveHTTPProbes() {
			probeURL := baseURL + probe.Request.Path
			wg.Add(1)
			go process(probeURL, probe.ID, probe.Request.Headers, responsesChannel, &mu, &wg, &errOccurred, nil)
		}
	}

	wg.Wait()

	close(responsesChannel)

	var responses []rules.Response
	for response := range responsesChannel {
		responses = append(responses, response)
	}
	var results []config.Result
	for _, match := range rules.MatchRules(responses, rules.ActiveRules()) {
		cms := match.Rule.Name
		if _, loaded := matchedCMS.LoadOrStore(cms, true); loaded {
			continue
		}
		response := preferredResponse(responses, match.Response)
		result := config.Result{
			URL:        response.URL,
			CMS:        cms,
			Category:   match.Rule.Category,
			Server:     response.Server,
			StatusCode: response.StatusCode,
			Title:      response.Title,
			Confidence: match.Confidence,
			Evidence:   match.Evidence,
		}
		results = append(results, result)
		logger.Success("[%s] [%s] [%d] [%s] [%s] [confidence=%d%%]", result.URL, result.CMS, result.StatusCode, result.Server, result.Title, result.Confidence)
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
	return rules.TLSInfo{
		Subject:  cert.Subject.String(),
		Issuer:   cert.Issuer.String(),
		DNSNames: cert.DNSNames,
		ALPN:     resp.TLS.NegotiatedProtocol,
	}
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
		url = strings.TrimSpace(url)
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

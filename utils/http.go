package utils

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/tjfoc/gmsm/gmtls"
	gmX509 "github.com/tjfoc/gmsm/x509"
	"golang.org/x/net/http2"
	"hfinger/logger"
)

var (
	httpClient          *http.Client
	clientCertPath      string
	clientKeyPath       string
	gmClientCertPath    string
	gmClientKeyPath     string
	tlsMode             = TLSModeAuto
	noScriptRe          = regexp.MustCompile(`(?is)<noscript[^>]*>.*?</noscript>`)
	metaRefreshRe       = regexp.MustCompile(`(?is)<meta\b[^>]*http-equiv\s*=\s*['"]?refresh['"]?[^>]*>`)
	jsLocationHrefRe    = regexp.MustCompile(`>window\.location\.href\s*=\s*['"]([^'"]+)['"]\s*;?\s*</script>`)
	jsLocationReplaceRe = regexp.MustCompile(`>window\.location\.replace\s*$\s*['"]([^'"]+)['"]\s*$\s*;?\s*</script>`)
	userAgents          = []string{
		// Desktop User Agents
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
		"Mozilla/5.0 (Windows NT 6.1; WOW64; rv:89.0) Gecko/20100101 Firefox/89.0",
		"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101 Firefox/91.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edg/91.0.864.64 Safari/537.36",
		"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",

		// Mobile User Agents
		"Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/537.36 (KHTML, like Gecko) Version/14.6 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (iPad; CPU OS 14_6 like Mac OS X) AppleWebKit/537.36 (KHTML, like Gecko) Version/14.6 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (Android 11; Mobile; rv:91.0) Gecko/91.0 Firefox/91.0",
		"Mozilla/5.0 (Linux; Android 11; Pixel 4 XL Build/RQ3A.210605.001) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Mobile Safari/537.36",
		"Mozilla/5.0 (Linux; Android 11; SM-G998U Build/RP1A.200720.012) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Mobile Safari/537.36",
		"Mozilla/5.0 (Linux; Android 11; SM-A515F Build/RP1A.200720.012) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Mobile Safari/537.36",
		"Mozilla/5.0 (Android 10; Mobile; rv:84.0) Gecko/84.0 Firefox/84.0",
		"Mozilla/5.0 (Android 10; Tablet; rv:84.0) Gecko/84.0 Firefox/84.0",

		// Other Common User Agents
		"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.85 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.82 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:90.0) Gecko/20100101 Firefox/90.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; Trident/7.0; AS; rv:11.0) like Gecko",
	}

	// 共享的国密TLS配置（提升性能）
	gmTLSConfig = &gmtls.Config{
		GMSupport:          &gmtls.GMSupport{},
		InsecureSkipVerify: true,
		RootCAs:            gmX509.NewCertPool(),
		NextProtos:         []string{"h2", "http/1.1"},
	}

	// 连接跟踪器（用于监控复用）
	connTrackMutex sync.Mutex
	connTrackMap   = make(map[string]int)
)

const (
	TLSModeAuto = "auto"
	TLSModeGM   = "gm"
	TLSModeStd  = "std"
)

var supportedGMTLSCipherSuites = []uint16{
	gmtls.GMTLS_SM2_WITH_SM4_SM3,
	gmtls.GMTLS_ECDHE_SM2_WITH_SM4_SM3,
}

const gmTLSCapabilitySummary = "supported GM/TLS stack: GM/T 0024-2014 VersionGMSSL(0x0101), cipher suites: GMTLS_SM2_WITH_SM4_SM3(0xe013), GMTLS_ECDHE_SM2_WITH_SM4_SM3(0xe011)"

func init() {
	rand.Seed(time.Now().UnixNano())
}

func RandomUserAgent() string {
	return userAgents[rand.Intn(len(userAgents))]
}

func ConfigureClientCertificates(certPath, keyPath, gmCertPath, gmKeyPath string) {
	clientCertPath = certPath
	clientKeyPath = keyPath
	gmClientCertPath = gmCertPath
	gmClientKeyPath = gmKeyPath
}

func ConfigureTLSMode(mode string) error {
	if mode == "" {
		mode = TLSModeAuto
	}
	switch mode {
	case TLSModeAuto, TLSModeGM, TLSModeStd:
		tlsMode = mode
		return nil
	default:
		return fmt.Errorf("invalid tls mode %q, allowed values: auto, gm, std", mode)
	}
}

func SupportedGMTLSCipherSuites() []uint16 {
	return append([]uint16(nil), supportedGMTLSCipherSuites...)
}

func InitializeHTTPClient(proxy string, timeout time.Duration, maxRedirects int) error {
	transport, err := createHybridTransport(proxy)
	if err != nil {
		return err
	}

	if err := http2.ConfigureTransport(transport); err != nil {
		// 回退到HTTP/1.1
		transport.ForceAttemptHTTP2 = false
	}

	httpClient = &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// 当重定向次数超过设定值时返回错误
			if len(via) > maxRedirects {
				return fmt.Errorf("stopped after %d redirects", maxRedirects)
			}
			return nil
		},
	}

	return nil
}

func createHybridTransport(proxy string) (*http.Transport, error) {
	stdClientCerts, gmClientCerts, err := loadClientCertificates()
	if err != nil {
		return nil, err
	}

	// 标准TLS配置
	stdTLSConfig := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2", "http/1.1"},
		Certificates:       stdClientCerts,
	}

	gmTLSConfig := &gmtls.Config{
		GMSupport:          &gmtls.GMSupport{},
		InsecureSkipVerify: true,
		RootCAs:            gmX509.NewCertPool(),
		NextProtos:         []string{"h2", "http/1.1"},
		CipherSuites:       supportedGMTLSCipherSuites,
		Certificates:       gmClientCerts,
	}
	tlsConnector := newActiveTLSConnector(tlsMode, stdTLSConfig, gmTLSConfig)

	// 创建混合传输层
	transport := &http.Transport{
		DialTLS: tlsConnector.Dial,

		DisableKeepAlives:   false,
		MaxIdleConns:        100,
		IdleConnTimeout:     120 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
		MaxConnsPerHost:     0,
		MaxIdleConnsPerHost: 50,
	}

	if proxy != "" {
		proxyURL, err := url.Parse(proxy)
		if err != nil {
			logger.Error("Error: %v", err)
			return transport, nil
		}

		transport.Proxy = http.ProxyURL(proxyURL)
	}

	return transport, nil
}

type activeTLSConnector struct {
	mode      string
	stdConfig *tls.Config
	gmConfig  *gmtls.Config
	stdDial   func(network, addr string, tlsConfig *tls.Config) (net.Conn, error)
	gmDial    func(network, addr string, tlsConfig *gmtls.Config) (net.Conn, error)
}

func newActiveTLSConnector(mode string, stdConfig *tls.Config, gmConfig *gmtls.Config) *activeTLSConnector {
	if mode == "" {
		mode = TLSModeAuto
	}
	return &activeTLSConnector{
		mode:      mode,
		stdConfig: stdConfig,
		gmConfig:  gmConfig,
		stdDial:   dialStandardTLS,
		gmDial:    connectWithGMTLS,
	}
}

func dialStandardTLS(network, addr string, tlsConfig *tls.Config) (net.Conn, error) {
	return tls.Dial(network, addr, tlsConfig)
}

func (connector *activeTLSConnector) Dial(network, addr string) (net.Conn, error) {
	if connector.mode == TLSModeGM {
		return connector.gmDial(network, addr, connector.gmConfig)
	}

	conn, err := connector.stdDial(network, addr, connector.stdConfig)
	if err == nil {
		return conn, nil
	}
	if connector.mode == TLSModeStd {
		return nil, err
	}
	if shouldFallbackToGMTLS(err) {
		logger.Warn("Standard TLS connection failed for %s, trying GM/TLS fallback: %v", addr, err)
		gmConn, gmErr := connector.gmDial(network, addr, connector.gmConfig)
		if gmErr == nil {
			return gmConn, nil
		}
		return nil, fmt.Errorf("standard TLS failed: %v; GM/TLS fallback failed: %w", err, gmErr)
	}
	return nil, err
}

func loadClientCertificates() ([]tls.Certificate, []gmtls.Certificate, error) {
	if (clientCertPath == "") != (clientKeyPath == "") {
		return nil, nil, fmt.Errorf("--client-cert and --client-key must be used together")
	}
	if (gmClientCertPath == "") != (gmClientKeyPath == "") {
		return nil, nil, fmt.Errorf("--gm-client-cert and --gm-client-key must be used together")
	}

	var stdCerts []tls.Certificate
	var gmCerts []gmtls.Certificate
	if clientCertPath != "" {
		cert, err := tls.LoadX509KeyPair(clientCertPath, clientKeyPath)
		if err != nil {
			return nil, nil, fmt.Errorf("load TLS client certificate: %w", err)
		}
		stdCerts = append(stdCerts, cert)

		gmCert, err := gmtls.LoadX509KeyPair(clientCertPath, clientKeyPath)
		if err == nil {
			gmCerts = append(gmCerts, gmCert)
		}
	}
	if gmClientCertPath != "" {
		gmCert, err := gmtls.LoadX509KeyPair(gmClientCertPath, gmClientKeyPath)
		if err != nil {
			return nil, nil, fmt.Errorf("load GM/TLS client certificate: %w", err)
		}
		gmCerts = append(gmCerts, gmCert)
	}
	return stdCerts, gmCerts, nil
}

func shouldFallbackToGMTLS(err error) bool {
	if err == nil {
		return false
	}
	errText := strings.ToLower(err.Error())
	gmTLSSignals := []string{
		"tls: protocol version not supported",
		"tls: handshake failure",
		"tls: illegal parameter",
		"tls: first record does not look like a tls handshake",
		"remote error: tls: handshake failure",
		"remote error: tls: protocol version not supported",
		"unsupported protocol",
	}
	for _, signal := range gmTLSSignals {
		if strings.Contains(errText, signal) {
			return true
		}
	}
	return false
}

func connectWithGMTLS(network, addr string, tlsConfig *gmtls.Config) (net.Conn, error) {
	conn, err := gmtls.Dial(network, addr, tlsConfig)
	if err != nil {
		return nil, formatGMTLSConnectError(err)
	}

	state := conn.ConnectionState()
	if !state.HandshakeComplete {
		conn.Close()
		return nil, fmt.Errorf("GM TLS handshake not complete")
	}

	return conn, nil
}

func formatGMTLSConnectError(err error) error {
	if err == nil {
		return nil
	}
	if isUnsupportedGMTLSStackError(err) {
		return fmt.Errorf("GM TLS connection failed: %v; target may require an unsupported GM/TLS version or cipher suite; %s", err, gmTLSCapabilitySummary)
	}
	return fmt.Errorf("GM TLS connection failed: %v", err)
}

func isUnsupportedGMTLSStackError(err error) bool {
	if err == nil {
		return false
	}
	errText := strings.ToLower(err.Error())
	signals := []string{
		"unsupported protocol version",
		"server selected unsupported protocol version",
		"unsupported cipher suite",
		"no cipher suite supported",
		"cipher suite",
		"handshake failure",
		"illegal parameter",
	}
	for _, signal := range signals {
		if strings.Contains(errText, signal) {
			return true
		}
	}
	return false
}

func setRequestHeaders(req *http.Request, headers map[string]string) {
	req.Header.Set("User-Agent", RandomUserAgent())
	req.Header.Set("Accept", "*/*;q=0.8")

	hasContentType := false
	if headers != nil {
		for key, value := range headers {
			if strings.EqualFold(key, "Content-Type") {
				hasContentType = true
			}
			req.Header.Set(key, value)
		}
	}

	// 仅对需要正文的方法设置默认 Content-Type
	if req.Body != nil && !hasContentType {
		switch req.Method {
		case "POST", "PUT", "PATCH", "DELETE":
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
		}
	}
}

func Head(url string, headers map[string]string) (*http.Response, error) {
	if httpClient == nil {
		return nil, fmt.Errorf("HTTP client not initialized.")
	}

	req, err := http.NewRequest("HEAD", url, nil)
	if err != nil {
		return nil, err
	}

	setRequestHeaders(req, headers)
	return httpClient.Do(req)
}

func Get(url string, headers map[string]string) (*http.Response, error) {
	if httpClient == nil {
		return nil, fmt.Errorf("HTTP client not initialized.")
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	setRequestHeaders(req, headers)
	return httpClient.Do(req)
}

func Options(url string, headers map[string]string) (*http.Response, error) {
	if httpClient == nil {
		return nil, fmt.Errorf("HTTP client not initialized.")
	}

	req, err := http.NewRequest("OPTIONS", url, nil)
	if err != nil {
		return nil, err
	}

	setRequestHeaders(req, headers)
	return httpClient.Do(req)
}

func Trace(url string, headers map[string]string) (*http.Response, error) {
	if httpClient == nil {
		return nil, fmt.Errorf("HTTP client not initialized.")
	}

	req, err := http.NewRequest("TRACE", url, nil)
	if err != nil {
		return nil, err
	}

	setRequestHeaders(req, headers)
	return httpClient.Do(req)
}

func Post(url string, data []byte, headers map[string]string) (*http.Response, error) {
	if httpClient == nil {
		return nil, fmt.Errorf("HTTP client not initialized.")
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(data))
	if err != nil {
		return nil, err
	}

	setRequestHeaders(req, headers)
	return httpClient.Do(req)
}

func Put(url string, data []byte, headers map[string]string) (*http.Response, error) {
	if httpClient == nil {
		return nil, fmt.Errorf("HTTP client not initialized.")
	}

	req, err := http.NewRequest("PUT", url, bytes.NewBuffer(data))
	if err != nil {
		return nil, err
	}

	setRequestHeaders(req, headers)
	return httpClient.Do(req)
}

func Delete(url string, data []byte, headers map[string]string) (*http.Response, error) {
	if httpClient == nil {
		return nil, fmt.Errorf("HTTP client not initialized.")
	}

	req, err := http.NewRequest("DELETE", url, bytes.NewBuffer(data))
	if err != nil {
		return nil, err
	}

	setRequestHeaders(req, headers)
	return httpClient.Do(req)
}

func FetchTitle(body []byte) string {
	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(body))
	if err != nil {
		return ""
	}
	title := doc.Find("title").Text()
	title = strings.TrimSpace(title)
	return title
}

func FetchFavicon(body []byte) string {
	doc, err := goquery.NewDocumentFromReader(bytes.NewReader([]byte(body)))
	if err != nil {
		return ""
	}

	var faviconURL string
	doc.Find("link[rel='icon'], link[rel='shortcut icon']").Each(func(i int, s *goquery.Selection) {
		href, exists := s.Attr("href")
		if exists {
			faviconURL = href
			return
		}
	})
	if faviconURL == "" {
		faviconURL = "/favicon.ico"
	}

	return faviconURL
}

func GetBaseURL(fullURL string) (string, error) {
	parsedURL, err := url.Parse(fullURL)
	if err != nil {
		return "", err
	}
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return "", fmt.Errorf("invalid URL scheme %q, only http and https are supported", parsedURL.Scheme)
	}
	if parsedURL.Host == "" {
		return "", fmt.Errorf("invalid URL %q: missing host", fullURL)
	}

	baseURL := fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)
	return baseURL, nil
}

// ExtractRedirectURL 从HTTP响应中提取重定向URL
func ExtractRedirectURL(resp *http.Response, body []byte) string {
	// 1. 检查HTTP Location头（标准重定向）
	if location := resp.Header.Get("Location"); location != "" {
		return location
	}

	// 2. 检查Refresh头
	if refresh := resp.Header.Get("Refresh"); refresh != "" {
		if urlStart := strings.Index(strings.ToLower(refresh), "url="); urlStart != -1 {
			return strings.TrimSpace(refresh[urlStart+4:])
		}
	}

	// 3. 检查HTML Meta Refresh（自动跳转）
	cleanBody := noScriptRe.ReplaceAll(body, []byte{})
	if metaTag := metaRefreshRe.Find(cleanBody); len(metaTag) > 0 {
		if content := extractHTMLAttribute(metaTag, "content"); content != "" {
			if urlStart := strings.Index(strings.ToLower(content), "url="); urlStart != -1 {
				return strings.TrimSpace(content[urlStart+4:])
			}
		}
	}

	// 4. 检查特定JavaScript跳转模式
	return extractSpecificJSRredirect(body)
}

// 专门处理两种特定的JavaScript跳转
func extractSpecificJSRredirect(body []byte) string {
	// 模式1: window.location.href = "URL";
	matches1 := jsLocationHrefRe.FindSubmatch(body)
	if len(matches1) > 1 {
		return string(matches1[1])
	}

	// 模式2: window.location.replace("URL");
	matches2 := jsLocationReplaceRe.FindSubmatch(body)
	if len(matches2) > 1 {
		return string(matches2[1])
	}

	return ""
}

func extractHTMLAttribute(tag []byte, name string) string {
	tagStr := string(tag)
	lowerTag := strings.ToLower(tagStr)
	lowerName := strings.ToLower(name)
	searchFrom := 0

	for {
		idx := strings.Index(lowerTag[searchFrom:], lowerName)
		if idx == -1 {
			return ""
		}
		idx += searchFrom
		beforeOK := idx == 0 || !isHTMLAttrNameChar(lowerTag[idx-1])
		after := idx + len(lowerName)
		afterOK := after < len(lowerTag) && !isHTMLAttrNameChar(lowerTag[after])
		if beforeOK && afterOK {
			pos := after
			for pos < len(tagStr) && isHTMLSpace(tagStr[pos]) {
				pos++
			}
			if pos >= len(tagStr) || tagStr[pos] != '=' {
				searchFrom = after
				continue
			}
			pos++
			for pos < len(tagStr) && isHTMLSpace(tagStr[pos]) {
				pos++
			}
			if pos >= len(tagStr) {
				return ""
			}

			if tagStr[pos] == '"' || tagStr[pos] == '\'' {
				quote := tagStr[pos]
				pos++
				end := strings.IndexByte(tagStr[pos:], quote)
				if end == -1 {
					return ""
				}
				return tagStr[pos : pos+end]
			}

			end := pos
			for end < len(tagStr) && !isHTMLSpace(tagStr[end]) && tagStr[end] != '>' {
				end++
			}
			return tagStr[pos:end]
		}
		searchFrom = after
	}
}

func isHTMLAttrNameChar(ch byte) bool {
	return ch == '-' || ch == '_' || ch == ':' || ch == '.' ||
		(ch >= '0' && ch <= '9') ||
		(ch >= 'a' && ch <= 'z') ||
		(ch >= 'A' && ch <= 'Z')
}

func isHTMLSpace(ch byte) bool {
	return ch == ' ' || ch == '\n' || ch == '\r' || ch == '\t' || ch == '\f'
}

// ResolveRelativeURL 解析相对URL为绝对URL
func ResolveRelativeURL(base, relative string) (string, error) {
	baseURL, err := url.Parse(base)
	if err != nil {
		return "", err
	}

	relURL, err := url.Parse(relative)
	if err != nil {
		return "", err
	}

	return baseURL.ResolveReference(relURL).String(), nil
}

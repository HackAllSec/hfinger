package utils

import (
    "bytes"
    "crypto/tls"
    "encoding/base64"
    "fmt"
    "math/rand"
    "net"
    "net/http"
    "net/url"
    "regexp"
    "strings"
    "sync"
    "time"
    
    "hfinger/logger"
    "golang.org/x/net/http2"
    "github.com/PuerkitoBio/goquery"
    "github.com/tjfoc/gmsm/gmtls"
    gmX509 "github.com/tjfoc/gmsm/x509"
)

var (
    httpClient *http.Client
    userAgents = []string{
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

func init() {
    rand.Seed(time.Now().UnixNano())
}

func RandomUserAgent() string {
    return userAgents[rand.Intn(len(userAgents))]
}

func InitializeHTTPClient(proxy string, timeout time.Duration, maxRedirects int) error {
    transport := createHybridTransport(proxy)
    
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

func createHybridTransport(proxy string) *http.Transport {
    // 标准TLS配置
    stdTLSConfig := &tls.Config{
        InsecureSkipVerify: true,
        NextProtos:         []string{"h2", "http/1.1"},
    }
    
    // 创建混合传输层
    transport := &http.Transport{
        DialTLS: func(network, addr string) (net.Conn, error) {
            conn, err := tls.Dial(network, addr, stdTLSConfig)
            if err == nil {
                return conn, nil
            }
            if strings.Contains(err.Error(), "tls: protocol version not supported") {
                return connectWithGMTLS(network, addr)
            }
            return nil, err
        },
        
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
            return transport
        }

        user := proxyURL.User.Username()
        password, hasPassword := proxyURL.User.Password()
        if hasPassword {
            encodedAuth := base64.StdEncoding.EncodeToString([]byte(user + ":" + password))
            transport.Proxy = func(req *http.Request) (*url.URL, error) {
                req.Header.Add("Proxy-Authorization", "Basic "+encodedAuth)
                return proxyURL, nil
            }
        } else {
            transport.Proxy = http.ProxyURL(proxyURL)
        }
    }
    
    return transport
}

func connectWithGMTLS(network, addr string) (net.Conn, error) {
    conn, err := gmtls.Dial(network, addr, gmTLSConfig)
    if err != nil {
        return nil, fmt.Errorf("GM TLS connection failed: %v", err)
    }
    
    state := conn.ConnectionState()
    if !state.HandshakeComplete {
        conn.Close()
        return nil, fmt.Errorf("GM TLS handshake not complete")
    }
    
    return conn, nil
}

func setRequestHeaders(req *http.Request, headers map[string]string) {
    req.Header.Set("User-Agent", RandomUserAgent())
    req.Header.Set("Accept", "*/*;q=0.8")
    
    if headers != nil {
        for key, value := range headers {
            req.Header.Set(key, value)
        }
    }
    
    // 仅对需要正文的方法设置默认 Content-Type
    if req.Body != nil {
        if _, exists := headers["Content-Type"]; !exists {
            switch req.Method {
            case "POST", "PUT", "PATCH", "DELETE":
                req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
            }
        }
    }
}

func Head(url string, headers map[string]string) (*http.Response, error) {
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
    req, err := http.NewRequest("POST", url, bytes.NewBuffer(data))
    if err != nil {
        return nil, err
    }
    
    setRequestHeaders(req, headers)
    return httpClient.Do(req)
}

func Put(url string, data []byte, headers map[string]string) (*http.Response, error) {
    req, err := http.NewRequest("PUT", url, bytes.NewBuffer(data))
    if err != nil {
        return nil, err
    }

    setRequestHeaders(req, headers)
    return httpClient.Do(req)
}

func Delete(url string, data []byte, headers map[string]string) (*http.Response, error) {
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
        if urlStart := strings.Index(refresh, "url="); urlStart != -1 {
            return strings.TrimSpace(refresh[urlStart+4:])
        }
    }
    
    // 3. 检查HTML Meta Refresh（自动跳转）
    re := regexp.MustCompile(`(?is)<noscript[^>]*>.*?</noscript>`)
    cleanBody := re.ReplaceAll(body, []byte{})
    if metaIdx := bytes.Index(body, []byte("http-equiv=\"refresh\"")); metaIdx != -1 {
        if contentIdx := bytes.Index(cleanBody[metaIdx:], []byte("content=")); contentIdx != -1 {
            start := metaIdx + contentIdx + 8 // 跳过 content=
            if start < len(body) {
                // 查找值结束引号
                quote := body[start]
                if quote == '"' || quote == '\'' {
                    end := bytes.IndexByte(body[start+1:], quote)
                    if end > 0 {
                        content := string(body[start+1 : start+1+end])
                        if urlStart := strings.Index(content, "url="); urlStart != -1 {
                            return strings.TrimSpace(content[urlStart+4:])
                        }
                    }
                }
            }
        }
    }
    
    // 4. 检查特定JavaScript跳转模式
    return extractSpecificJSRredirect(body)
}

// 专门处理两种特定的JavaScript跳转
func extractSpecificJSRredirect(body []byte) string {
    // 模式1: window.location.href = "URL";
    re1 := regexp.MustCompile(`>window\.location\.href\s*=\s*['"]([^'"]+)['"]\s*;?\s*</script>`)
    matches1 := re1.FindSubmatch(body)
    if len(matches1) > 1 {
        return string(matches1[1])
    }
    
    // 模式2: window.location.replace("URL");
    re2 := regexp.MustCompile(`>window\.location\.replace\s*$\s*['"]([^'"]+)['"]\s*$\s*;?\s*</script>`)
    matches2 := re2.FindSubmatch(body)
    if len(matches2) > 1 {
        return string(matches2[1])
    }

    return ""
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

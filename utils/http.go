package utils

import (
    "bytes"
    "crypto/tls"
    "fmt"
    "math/rand"
    "net/http"
    "net/url"
    "strings"
    "time"
    "os"
    "io"
    "io/ioutil"
    "encoding/json"

    "github.com/PuerkitoBio/goquery"
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
)

func RandomUserAgent() string {
    rand.Seed(time.Now().UnixNano())
    return userAgents[rand.Intn(len(userAgents))]
}

func InitializeHTTPClient(proxy string, timeout time.Duration) error {
    transport := &http.Transport{
        TLSClientConfig: &tls.Config{
            InsecureSkipVerify: true,
        },
    }

    if proxy != "" {
        proxyURL, err := url.Parse(proxy)
        if err != nil {
            return fmt.Errorf("Error: %v", err)
        }
        transport.Proxy = http.ProxyURL(proxyURL)
    }

    httpClient = &http.Client{
        Transport: transport,
        Timeout:   timeout,
    }
    return nil
}

func Head(url string, headers map[string]string) (*http.Response, error) {
    req, err := http.NewRequest("HEAD", url, nil)
    if err != nil {
        return nil, err
    }

    req.Header.Set("User-Agent", RandomUserAgent())
    req.Header.Set("Accept", "*/*;q=0.8")

    if headers != nil {
        for key, value := range headers {
            req.Header.Set(key, value)
        }
    }

    resp, err := httpClient.Do(req)
    if err != nil {
        return nil, err
    }

    return resp, nil
}

func Get(url string, headers map[string]string) (*http.Response, error) {
    if httpClient == nil {
        return nil, fmt.Errorf("Error: HTTP client not initialized")
    }

    req, err := http.NewRequest("GET", url, nil)
    if err != nil {
        return nil, err
    }

    req.Header.Set("User-Agent", RandomUserAgent())
    req.Header.Set("Accept", "*/*;q=0.8")

    if headers != nil {
        for key, value := range headers {
            req.Header.Set(key, value)
        }
    }

    resp, err := httpClient.Do(req)
    if err != nil {
        return nil, err
    }

    return resp, nil
}

func Post(turl string, data interface{}, headers map[string]string) (*http.Response, error) {
    var body io.Reader
    var contentType string
    switch v := data.(type) {
    case string:
        body = bytes.NewBufferString(v)
        contentType = "text/plain; charset=utf-8"
    case map[string]string:
        formData := url.Values{}
        for key, value := range v {
            formData.Add(key, value)
        }
        body = strings.NewReader(formData.Encode())
        contentType = "application/x-www-form-urlencoded"
    case *os.File:
        fileData, err := ioutil.ReadAll(v)
        if err != nil {
            return nil, err
        }
        body = bytes.NewBuffer(fileData)
        contentType = http.DetectContentType(fileData)
    default:
        jsonData, err := json.Marshal(v)
        if err != nil {
            return nil, err
        }
        body = bytes.NewBuffer(jsonData)
        contentType = "application/json"
    }

    req, err := http.NewRequest("POST", turl, body)
    if err != nil {
        return nil, err
    }
    req.Header.Set("Content-Type", contentType)
    req.Header.Set("User-Agent", RandomUserAgent())
    req.Header.Set("Accept", "*/*;q=0.8")

    if headers != nil {
        for key, value := range headers {
            req.Header.Set(key, value)
        }
    }

    resp, err := httpClient.Do(req)
    if err != nil {
        return nil, err
    }

    return resp, nil
}

func Put(url string, data interface{}, headers map[string]string) (*http.Response, error) {
    jsonStr, err := json.Marshal(data)
    if err != nil {
        return nil, err
    }

    req, err := http.NewRequest("PUT", url, bytes.NewBuffer(jsonStr))
    if err != nil {
        return nil, err
    }

    // Set headers
    req.Header.Set("Content-Type", "application/json")
    req.Header.Set("User-Agent", RandomUserAgent())
    req.Header.Set("Accept", "*/*;q=0.8")

    if headers != nil {
        for key, value := range headers {
            req.Header.Set(key, value)
        }
    }

    resp, err := httpClient.Do(req)
    if err != nil {
        return nil, err
    }

    return resp, nil
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
        return "", fmt.Errorf("Error: %w", err)
    }

    baseURL := fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)
    return baseURL, nil
}

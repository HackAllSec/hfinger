package models

import (
    "fmt"
    "io"
    "os"
    "net/http"
    "strings"
    "sync"
    "time"
    "math/rand"

    "hfinger/config"
    "hfinger/utils"
    "hfinger/output"
    "github.com/fatih/color"
)

var (
    workerCount int64
    maxRedirects int64
    outputLock sync.Mutex // 全局锁保护output操作
)

func process(url string, headers map[string]string, resultsChannel chan<- config.Result, matchedCMS *sync.Map, mu *sync.Mutex, wg *sync.WaitGroup, errOccurred *bool, saveResponse func(int, string, string)) {
    defer wg.Done()
    
    currentURL := url
    redirectCount := int64(0)
    processedFirst := false

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
                *errOccurred = handleError(err, currentURL)
            }
            mu.Unlock()
            return
        }
        
        // 读取响应后立即关闭body
        body, err := io.ReadAll(resp.Body)
        resp.Body.Close()
        if err != nil {
            color.Red("[%s] [!] Error: %v", time.Now().Format("01-02 15:04:05"), err)
            return
        }

        title := utils.FetchTitle(body)
        if title == "" {
            title = "None"
        }

        faviconpath := utils.FetchFavicon(body)
        var faviconbody []byte
        if faviconpath != "" && resp.StatusCode == http.StatusOK {
            baseurl, _ := utils.GetBaseURL(currentURL)
            faviconurl := baseurl + "/" + faviconpath
            if strings.HasPrefix(faviconpath, "http://") || strings.HasPrefix(faviconpath, "https://") {
                faviconurl = faviconpath
            }
            if faviconpath[0] == '/' {
                faviconurl = baseurl + faviconpath
            }
            favicon, err := utils.Get(faviconurl, nil)
            if err == nil && favicon.StatusCode == http.StatusOK {
                defer favicon.Body.Close()
                faviconbody, err = io.ReadAll(favicon.Body)
                if err != nil {
                    color.Yellow("[%s] [-] Warning: %v", time.Now().Format("01-02 15:04:05"), err)
                }
            }
        }

        statusCode := resp.StatusCode
        server := resp.Header.Get("Server")
        if server == "" {
            server = "None"
        }

        // 保存第一次请求结果
        if saveResponse != nil && !processedFirst {
            saveResponse(statusCode, server, title)
            processedFirst = true
        }

        // 指纹匹配
        for _, fingerprint := range config.Config.Finger {
            ismatched := matchKeywords(body, resp.Header, title, faviconbody, fingerprint)
            if ismatched {
                cms := fingerprint.CMS
                if _, loaded := matchedCMS.LoadOrStore(cms, true); !loaded {
                    result := config.Result{
                        URL:        currentURL, // 使用当前URL（可能是重定向后的）
                        CMS:        cms,
                        Server:     server,
                        StatusCode: statusCode,
                        Title:      title,
                    }
                    resultsChannel <- result
                    color.Green("[%s] [+] [%s] [%s] [%d] [%s] [%s]",
                        time.Now().Format("01-02 15:04:05"), currentURL, cms, statusCode, server, title)
                }
            }
        }

        // 检查是否需要重定向
        if redirectCount < maxRedirects && 
            (statusCode == http.StatusMovedPermanently ||
             statusCode == http.StatusFound ||
             statusCode == http.StatusSeeOther ||
             statusCode == http.StatusTemporaryRedirect) {
            
            location := resp.Header.Get("Location")
            if location == "" {
                return
            }
            
            // 处理相对路径重定向
            if !strings.HasPrefix(location, "http://") && !strings.HasPrefix(location, "https://") {
                baseurl, _ := utils.GetBaseURL(currentURL)
                if strings.HasPrefix(location, "/") {
                    location = baseurl + location
                } else {
                    location = baseurl + "/" + location
                }
            }
            
            currentURL = location
            redirectCount++
            continue // 处理重定向
        }
        
        break // 退出循环
    }
}

func ProcessURL(url string) {
    var wg sync.WaitGroup
    var mu sync.Mutex
    var errOccurred bool
    var matchedCMS sync.Map
    resultsChannel := make(chan config.Result, workerCount)

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

    // 统一处理所有请求
    wg.Add(3) // 三个请求：原始URL两次，随机路径一次
    go process(url, nil, resultsChannel, &matchedCMS, &mu, &wg, &errOccurred, saveFirstResponse)
    go process(url, map[string]string{"Cookie": "rememberMe=1"}, resultsChannel, &matchedCMS, &mu, &wg, &errOccurred, saveFirstResponse)
    
    // 构造带随机路径的新 URL
    suffix := fmt.Sprintf("/%x", rand.Int())
    if url[len(url)-1] == '/' {
        suffix = fmt.Sprintf("%x", rand.Int())
    }
    newUrl := url + suffix
    go process(newUrl, nil, resultsChannel, &matchedCMS, &mu, &wg, &errOccurred, nil)
    
    wg.Wait()

    close(resultsChannel)

    var results []config.Result
    for result := range resultsChannel {
        results = append(results, result)
    }

    // 使用全局锁保护output操作
    outputLock.Lock()
    defer outputLock.Unlock()
    for _, result := range results {
        output.AddResults(result)
    }

    mu.Lock()
    defer mu.Unlock()
    if countItems(&matchedCMS) == 0 && !errOccurred {
        color.White("[%s] [*] [%s] [Not Matched] [%d] [%s] [%s]",
            time.Now().Format("01-02 15:04:05"),
            url,
            lastResp.StatusCode,
            lastResp.Server,
            lastResp.Title)
    }
}

func countItems(m *sync.Map) int {
    count := 0
    m.Range(func(_, _ interface{}) bool {
        count++
        return true
    })
    return count
}

func handleError(err error, url string) bool {
    if strings.Contains(err.Error(), "dial tcp: lookup") {
        color.Red("[%s] [!] Error: Domain name resolution failed %s", time.Now().Format("01-02 15:04:05"), url)
        return true
    } else if strings.Contains(err.Error(), "No connection could be made") {
        color.Red("[%s] [!] Error: The target host rejected the connection request %s", time.Now().Format("01-02 15:04:05"), url)
        return true
    } else if strings.Contains(err.Error(), "Client.Timeout") {
        color.Red("[%s] [!] Error: Request timeout %s", time.Now().Format("01-02 15:04:05"), url)
        return true
    } else if strings.Contains(err.Error(), "An existing connection was forcibly closed by the remote host") {
        return false
    } else {
        color.Red("[%s] [!] Error: %s %s", time.Now().Format("01-02 15:04:05"), err, url)
        return true
    }
}

func ProcessFile(filePath string) {
    data, err := os.ReadFile(filePath)
    if err != nil {
        color.Red("[%s] [!] Error: %s", time.Now().Format("01-02 15:04:05"), err)
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
    
    // 所有URL处理完成后统一写入文件
    outputLock.Lock()
    defer outputLock.Unlock()
    if err := output.WriteOutputs(); err != nil {
        color.Red("[%s] [!] Error writing output: %s", time.Now().Format("01-02 15:04:05"), err)
    }
}

func SetThread(thread int64) {
    workerCount = thread
}

func SetMaxRedirects(count int64) {
    maxRedirects = count
}

func ShowFingerPrints() {
    fingerprints := config.Config
    fingerCount := len(fingerprints.Finger)
    color.Blue("[*] Total number of fingerprints: %d\n", fingerCount)
    uniqueCMSCount := make(map[string]struct{})
    uniqueCount := 0
    for _, fp := range fingerprints.Finger {
        if _, exists := uniqueCMSCount[fp.CMS]; !exists {
            uniqueCMSCount[fp.CMS] = struct{}{}
            uniqueCount++
        }
    }
    color.Blue("[*] Total number of products, web frameworks, and CMS: %d\n", uniqueCount)
}
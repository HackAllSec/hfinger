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
    resultsLock sync.Mutex
    cfg *config.FingerprintConfig = config.GetConfig()
)

func process(url string, headers map[string]string, resultsChannel chan<- config.Result, matchedCMS *sync.Map, mu *sync.Mutex, wg *sync.WaitGroup, errOccurred *bool) {
    defer wg.Done()

    mu.Lock()
    if *errOccurred {
        mu.Unlock()
        return
    }
    mu.Unlock()
    
    resp, err := utils.Get(url, headers)
    if err != nil {
        mu.Lock()
        if !*errOccurred {
            *errOccurred = handleError(err, url)
        }
        mu.Unlock()
        return
    }
    defer resp.Body.Close()

    body, err := io.ReadAll(resp.Body)
    if err != nil {
        color.Red("[%s] [!] Error: %s", time.Now().Format("01-02 15:04:05"), err)
        return
    }

    title := utils.FetchTitle(body)
    if title == "" {
        title = "None"
    }
    faviconpath := utils.FetchFavicon(body)
    var faviconbody []byte
    if faviconpath != "" && resp.StatusCode == http.StatusOK {
        baseurl, _ := utils.GetBaseURL(url)
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
                color.Yellow("[%s] [-] Warning: %s", time.Now().Format("01-02 15:04:05"), err)
            }
        }
    }

    statuscode := resp.StatusCode
    server := resp.Header.Get("Server")
    if server == "" {
        server = "None"
    }
    for _, fingerprint := range cfg.Finger {
        ismatched := matchKeywords(body, resp.Header, title, faviconbody, fingerprint)
        if ismatched {
            cms := fingerprint.CMS
            if _, loaded := matchedCMS.LoadOrStore(cms, true); !loaded {
                result := config.Result{
                    URL:        url,
                    CMS:        cms,
                    Server:     server,
                    StatusCode: statuscode,
                    Title:      title,
                }
                resultsChannel <- result
                color.Green("[%s] [+] [%s] [%s] [%d] [%s] [%s]", time.Now().Format("01-02 15:04:05"), url, cms, statuscode, server, title)
            }
        }
    }
    switch resp.StatusCode {
    case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect:
        location := resp.Header.Get("Location")
        baseurl, _ := utils.GetBaseURL(url)
        if !strings.HasPrefix(location, "http://") && !strings.HasPrefix(location, "https://") {
            location = baseurl + location
        }
        wg.Add(1)
        go process(location, nil, resultsChannel, matchedCMS, mu, wg, errOccurred)
    default:
        return
    }
}

func ProcessURL(url string) {
    var wg sync.WaitGroup
    var mu sync.Mutex
    var errOccurred bool
    var matchedCMS sync.Map
    resultsChannel := make(chan config.Result, workerCount)

    wg.Add(2)
    go process(url, nil, resultsChannel, &matchedCMS, &mu, &wg, &errOccurred)
    go process(url, map[string]string{"Cookie": "rememberMe=1"}, resultsChannel, &matchedCMS, &mu, &wg, &errOccurred)
    wg.Wait()

    wg.Add(1)
    suffix := fmt.Sprintf("/%x", rand.Int())
    if url[len(url)-1] == '/' {
        suffix = fmt.Sprintf("%x", rand.Int())
    }
    url = url + suffix
    go process(url, nil, resultsChannel, &matchedCMS, &mu, &wg, &errOccurred)
    wg.Wait()

    close(resultsChannel)

    var results []config.Result
    for result := range resultsChannel {
        results = append(results, result)
    }

    resultsLock.Lock()
    defer resultsLock.Unlock()
    for _, result := range results {
        output.AddResults(result)
    }
    err := output.WriteOutputs()
    if err != nil {
        color.Red("[%s] [!] Error: %s", time.Now().Format("01-02 15:04:05"), err)
    }

    mu.Lock()
    defer mu.Unlock()
    if countItems(&matchedCMS) == 0 && !errOccurred {
        color.White("[%s] [*] [%s] [None] [%d] [None] [None]", time.Now().Format("01-02 15:04:05"), url, 0)
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
            defer func() {
                <-sem
            }()

            ProcessURL(u)
        }(url)
    }

    wg.Wait()
    close(sem)
}

func SetThread(thread int64) {
    workerCount = thread
}

func ShowFingerPrints() {
    fingerprints := config.GetConfig()
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

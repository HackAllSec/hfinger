package models

import (
    "fmt"
    "io/ioutil"
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
)

func MatchFingerprint(body []byte, header map[string][]string, title string, favicon []byte) (string, bool) {
    cfg := config.GetConfig()
    for _, fingerprint := range cfg.Finger {
        matched := matchKeywords(body, header, title, favicon, fingerprint)
        if matched {
            return fingerprint.CMS, true
        }
    }
    return "Not Matched", false
}

func ProcessURL(url string) {
    var wg sync.WaitGroup
    var mu sync.Mutex
    var errOccurred bool
    var matchedCMS map[string]bool = make(map[string]bool)
    var cms, server, title string
    statuscode := 0
    resultsChannel := make(chan config.Result, workerCount)

    process := func(url string, headers map[string]string) {
        defer wg.Done()

        if errOccurred {
            return
        }

        resp, err := utils.Get(url, headers)
        if err != nil {
            mu.Lock()
            if !errOccurred {
                errOccurred = true
                handleError(err, url)
            }
            mu.Unlock()
            return
        }
        defer resp.Body.Close()

        body, err := ioutil.ReadAll(resp.Body)
        if err != nil {
            color.Red("[%s] [!] Error: %s", time.Now().Format("01-02 15:04:05"), err)
            return
        }

        title = utils.FetchTitle(body)
        if title == "" {
            title = "None"
        }
        faviconpath := utils.FetchFavicon(body)
        var faviconbody []byte
        if faviconpath != "" {
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
                faviconbody, err = ioutil.ReadAll(favicon.Body)
                if err != nil {
                    color.Yellow("[%s] [-] Warning: %s", time.Now().Format("01-02 15:04:05"), err)
                }
            }
        }

        var ismatched bool
        cms, ismatched = MatchFingerprint(body, resp.Header, title, faviconbody)
        statuscode = resp.StatusCode
        server = resp.Header.Get("Server")
        if server == "" {
            server = "None"
        }
        result := config.Result{
            URL:        url,
            CMS:        cms,
            Server:     server,
            StatusCode: statuscode,
            Title:      title,
        }

        mu.Lock()
        defer mu.Unlock()

        if ismatched {
            if !matchedCMS[cms] {
                matchedCMS[cms] = true
                resultsChannel <- result
                color.Green("[%s] [+] [%s] [%s] [%d] [%s] [%s]", time.Now().Format("01-02 15:04:05"), url, cms, statuscode, server, title)
            }
        }
    }

    wg.Add(2)
    go process(url, nil)
    go process(url, map[string]string{"Cookie": "rememberMe=1"})
    wg.Wait()

    wg.Add(1)
    suffix := fmt.Sprintf("/%d", rand.Int())
    if url[len(url)-1] == '/' {
        suffix = fmt.Sprintf("%d", rand.Int())
    }
    url = url + suffix
    go process(url, nil)
    wg.Wait()

    close(resultsChannel)
    mu.Lock()
    defer mu.Unlock()

    if len(matchedCMS) == 0 && !errOccurred {
        color.White("[%s] [*] [%s] [%s] [%d] [%s] [%s]", time.Now().Format("01-02 15:04:05"), url, cms, statuscode, server, title)
    }

    resultsLock.Lock()
    defer resultsLock.Unlock()

    for result := range resultsChannel {
        //results = append(results, result)
        output.AddResults(result)
    }
    err := output.WriteOutputs()
    if err != nil {
        color.Red("[%s] [!] Error: %s", time.Now().Format("01-02 15:04:05"), err)
    }
}

func handleError(err error, url string) {
    if strings.Contains(err.Error(), "dial tcp: lookup") {
        color.Red("[%s] [!] Error: Domain name resolution failed %s", time.Now().Format("01-02 15:04:05"), url)
    } else if strings.Contains(err.Error(), "No connection could be made") {
        color.Red("[%s] [!] Error: The target host rejected the connection request %s", time.Now().Format("01-02 15:04:05"), url)
    } else if strings.Contains(err.Error(), "Client.Timeout") {
        color.Red("[%s] [!] Error: Request timeout %s", time.Now().Format("01-02 15:04:05"), url)
    } else {
        color.Red("[%s] [!] Error: %s %s", time.Now().Format("01-02 15:04:05"), err, url)
    }
}

func ProcessFile(filePath string) {
    data, err := ioutil.ReadFile(filePath)
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

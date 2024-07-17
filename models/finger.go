package models

import (
    "fmt"
    "io/ioutil"
    "net/http"
    "strings"
    "sync"
    "time"

    "hfinger/config"
    "hfinger/utils"
    "hfinger/output"
    "github.com/fatih/color"
)

var (
    workerCount int64
    results     []config.Result
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
    var once sync.Once
    resultsChannel := make(chan config.Result, workerCount)
    matched := false
    var cms, server, title string
    statuscode := 0

    process := func(reqFunc func(string) (*http.Response, error)) {
        defer wg.Done()

        if errOccurred {
            return
        }

        resp, err := reqFunc(url)
        if err != nil {
            once.Do(func() {
                errOccurred = true
                matched = true
                handleError(err, url)
            })
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
            favicon, err := utils.Get(faviconurl)
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

        if ismatched && !matched {
            matched = true
            resultsChannel <- result
            color.Green("[%s] [+] [%s] [%s] [%d] [%s] [%s]", time.Now().Format("01-02 15:04:05"), url, cms, statuscode, server, title)
        }
    }

    wg.Add(3)

    go process(utils.Get3)
    go process(utils.Get2)
    go process(utils.Get)

    wg.Wait()
    close(resultsChannel)

    if !matched {
        color.White("[%s] [*] [%s] [%s] [%d] [%s] [%s]", time.Now().Format("01-02 15:04:05"), url, cms, statuscode, server, title)
    }

    resultsLock.Lock()
    defer resultsLock.Unlock()

    for result := range resultsChannel {
        results = append(results, result)
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

func WriteOutputs(formats map[string]string) error {
    resultsLock.Lock()
    defer resultsLock.Unlock()

    for format, path := range formats {
        switch format {
        case "json":
            if err := output.WriteJSONOutput(path, results); err != nil {
                return err
            }
        case "xml":
            if err := output.WriteXMLOutput(path, results); err != nil {
                return err
            }
        case "xlsx":
            if err := output.WriteXLSXOutput(path, results); err != nil {
                return err
            }
        default:
            return fmt.Errorf("This type of file is not supported: %s", format)
        }
    }
    return nil
}

func SetThread(thread int64) {
    workerCount = thread
}

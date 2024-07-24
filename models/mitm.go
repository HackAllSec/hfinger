package models

import (
    "bufio"
    "crypto/tls"
    "io"
    "net"
    "net/http"
    "net/http/httputil"
    "time"
    "strings"

    "hfinger/config"
    "hfinger/output"
    "hfinger/utils"
    "github.com/fatih/color"
)

var (
    matchedCMS map[string]bool = make(map[string]bool)
)

func MitmServer(listenAddr string) {
    if err := utils.EnsureCerts(); err != nil {
        color.Red("[%s] [!] Error: %v", time.Now().Format("01-02 15:04:05"), err)
    }

    tlsConfig, err := utils.LoadCertificate()
    if err != nil {
        color.Red("[%s] [!] Error: %v", time.Now().Format("01-02 15:04:05"), err)
    }

    listener, err := net.Listen("tcp", listenAddr)
    if err != nil {
        color.Red("[%s] [!] Error: %v", time.Now().Format("01-02 15:04:05"), err)
    }
    defer listener.Close()

    color.White("[%s] [*] Starting MITM Server at: %s", time.Now().Format("01-02 15:04:05"), listenAddr)

    for {
        conn, err := listener.Accept()
        if err != nil {
            color.Red("[%s] [!] Error: %v", time.Now().Format("01-02 15:04:05"), err)
            continue
        }

        go handleConnection(conn, tlsConfig)
    }
}

// handleConnection
func handleConnection(conn net.Conn, tlsConfig *tls.Config) {
    defer conn.Close()
    reader := bufio.NewReader(conn)

    // Read HTTP Request
    req, err := http.ReadRequest(reader)
    if err != nil {
        color.Red("[%s] [!] Error: %v", time.Now().Format("01-02 15:04:05"), err)
        return
    }

    if req.Method == "CONNECT" {
        if err := handleHTTPS(conn, req, tlsConfig); err != nil {
            color.Red("[%s] [!] Error: %v", time.Now().Format("01-02 15:04:05"), err)
        }
    } else {
        if err := handleHTTP(conn, req); err != nil {
            color.Red("[%s] [!] Error: %v", time.Now().Format("01-02 15:04:05"), err)
        }
    }
}

func headersToMap(headers http.Header) map[string]string {
    headerMap := make(map[string]string)
    for key, values := range headers {
        if len(values) > 0 {
            headerMap[key] = values[0]
        }
    }
    return headerMap
}

// handleHTTP
func handleHTTP(conn net.Conn, req *http.Request) error {
    var resp *http.Response
    url := req.URL.String()
    httpMethod := req.Method
    headers := headersToMap(req.Header)
    var err error
    color.White("[%s] [*] Received HTTP request: %s", time.Now().Format("01-02 15:04:05"), url)
    switch httpMethod {
    case "GET":
        resp, err = utils.Get(url,headers)
        if err != nil {
            return err
        }
    case "POST":
        body, err := io.ReadAll(req.Body)
        if err != nil {
            return err
        }
        req.Body.Close()
        resp, err = utils.Post(url,body,headers)
        if err != nil {
            return err
        }
    case "PUT":
        body, err := io.ReadAll(req.Body)
        if err != nil {
            return err
        }
        req.Body.Close()
        resp, err = utils.Put(url,body,headers)
        if err != nil {
            return err
        }
    default:
        color.Red("[%s] [!] Error: Not supported %s Method!", time.Now().Format("01-02 15:04:05"), httpMethod)
        return nil
    }
    defer resp.Body.Close()
    responseDump, err := httputil.DumpResponse(resp, true)
    if err != nil {
        return err
    }
    conn.Write(responseDump)
    MitmMatchFingerprint(url, resp)
    return nil
}

// handleHTTPS
func handleHTTPS(conn net.Conn, req *http.Request, tlsConfig *tls.Config) error {
    var resp *http.Response
    baseurl := "https://" + req.Host
    _, err := conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
    if err != nil {
        return err
    }

    tlsConn := tls.Server(conn, tlsConfig)
    err = tlsConn.Handshake()
    if err != nil {
        return err
    }
    defer tlsConn.Close()

    // Read client http request
    reader := bufio.NewReader(tlsConn)
    clientReq, err := http.ReadRequest(reader)
    if err != nil {
        return err
    }

    httpsMethod := clientReq.Method
    httpsUrl := clientReq.URL.String()
    headers := headersToMap(clientReq.Header)
    url := baseurl + httpsUrl
    color.White("[%s] [*] Received HTTPS request: %s", time.Now().Format("01-02 15:04:05"), url)
    
    switch httpsMethod {
    case "GET":
        resp, err = utils.Get(url,headers)
        if err != nil {
            return err
        }
    case "POST":
        body, err := io.ReadAll(clientReq.Body)
        if err != nil {
            return err
        }
        clientReq.Body.Close()
        resp, err = utils.Post(url,body,headers)
        if err != nil {
            return err
        }
    case "PUT":
        body, err := io.ReadAll(clientReq.Body)
        if err != nil {
            return err
        }
        clientReq.Body.Close()
        resp, err = utils.Put(url,body,headers)
        if err != nil {
            return err
        }
    default:
        color.Red("[%s] [!] Error: Not supported %s Method!", time.Now().Format("01-02 15:04:05"), httpsMethod)
        return nil
    }
    defer resp.Body.Close()
    responseDump, err := httputil.DumpResponse(resp, true)
    if err != nil {
        return err
    }
    _, err = tlsConn.Write(responseDump)
    if err != nil {
        return err
    }
    MitmMatchFingerprint(url, resp)
    return nil
}

func MitmMatchFingerprint(url string, resp *http.Response) {
    var matched bool
    cfg := config.GetConfig()
    cms := "None"
    statuscode := resp.StatusCode
    header := resp.Header
    server := resp.Header.Get("Server")
    if server == "" {
        server = "None"
    }
    body, err := io.ReadAll(resp.Body)
    if err != nil {
        color.Red("[%s] [!] Error: %v", time.Now().Format("01-02 15:04:05"), err)
    }
    title := utils.FetchTitle(body)
    if title == "" {
        title = "None"
    }
    faviconurl := utils.FetchFavicon(body)
    if strings.Contains(url, faviconurl) && resp.StatusCode == http.StatusOK {
        for _, fingerprint := range cfg.Finger {
            matched = matchKeywords(nil, header, title, body, fingerprint)
            if matched {
                cms = fingerprint.CMS
                if !matchedCMS[cms] {
                    matchedCMS[cms] = true
                    color.Green("[%s] [+] [%s] [%s] [%d] [%s] [%s]", time.Now().Format("01-02 15:04:05"), url, cms, statuscode, server, title)
                    result := config.Result{
                        URL:        url,
                        CMS:        cms,
                        Server:     server,
                        StatusCode: statuscode,
                        Title:      title,
                    }
                    output.AddResults(result)
                }
            }
        }
        err = output.WriteOutputs()
        if err != nil {
            color.Red("[%s] [!] Error: %s", time.Now().Format("01-02 15:04:05"), err)
        }
    } else {
        for _, fingerprint := range cfg.Finger {
            matched = matchKeywords(body, header, title, nil, fingerprint)
            if matched {
                cms = fingerprint.CMS
                if !matchedCMS[cms] {
                    matchedCMS[cms] = true
                    color.Green("[%s] [+] [%s] [%s] [%d] [%s] [%s]", time.Now().Format("01-02 15:04:05"), url, cms, statuscode, server, title)
                    result := config.Result{
                        URL:        url,
                        CMS:        cms,
                        Server:     server,
                        StatusCode: statuscode,
                        Title:      title,
                    }
                    output.AddResults(result)
                }
            }
        }
        err = output.WriteOutputs()
        if err != nil {
            color.Red("[%s] [!] Error: %s", time.Now().Format("01-02 15:04:05"), err)
        }
    }
}

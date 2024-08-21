package models

import (
    "bufio"
    "bytes"
    "crypto/tls"
    "fmt"
    "io"
    "net"
    "net/http"
    "net/http/httputil"
    "time"
    "strings"
    "sync"
    "compress/gzip"
    "compress/zlib"

    "hfinger/config"
    "hfinger/output"
    "hfinger/utils"
    "github.com/fatih/color"
)

var (
    matchedCMS sync.Map
    certCache = sync.Map{}
)

func MitmServer(listenAddr string) {
    sem := make(chan struct{}, workerCount)
    if err := utils.EnsureCerts(); err != nil {
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
        sem <- struct{}{}
        go func(conn net.Conn) {
            defer func() { <-sem }()
            defer conn.Close()
            handleConnection(conn)
        }(conn)
    }
}

// handleConnection
func handleConnection(conn net.Conn) {
    defer conn.Close()
    reader := bufio.NewReader(conn)

    req, err := http.ReadRequest(reader)
    if err != nil {
        // Request reading error
        return
    }

    done := make(chan error, 1)

    go func() {
        var err error
        switch req.Method {
        case "CONNECT":
            err = handleHTTPS(conn, req)
        default:
            err = handleHTTP(conn, req)
        }
        done <- err
    }()

    if err := <-done; err != nil {
        color.Red("[%s] [!] Error: %v", time.Now().Format("01-02 15:04:05"), err)
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
    color.White("[%s] [*] Received HTTP request: %s", time.Now().Format("01-02 15:04:05"), req.URL.String())
    err := ForwardHTTPRequest(conn, req, false)
    if err != nil {
        return err
    }
    return nil
}

// handleHTTPS
func handleHTTPS(conn net.Conn, req *http.Request) error {
    defer conn.Close()

    host := req.URL.Host
    hostParts := strings.Split(host, ":")
    if len(hostParts) > 0 {
        host = hostParts[0]
    }

    tlsConfig, err := getTLSConfigForHost(host)
    if err != nil {
        return err
    }

    _, err = conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
    if err != nil {
        return err
    }

    tlsConn := tls.Server(conn, tlsConfig)
    err = tlsConn.Handshake()
    if err != nil {
        return err
    }
    defer tlsConn.Close()

    reader := bufio.NewReader(tlsConn)
    clientReq, err := http.ReadRequest(reader)
    if err != nil {
        return err
    }

    color.White("[%s] [*] Received HTTPS request: %s", time.Now().Format("01-02 15:04:05"), "https://" + clientReq.Host + clientReq.URL.Path)
    err = ForwardHTTPRequest(tlsConn, clientReq, true)
    if err != nil {
        return err
    }
    return nil
}

func getTLSConfigForHost(host string) (*tls.Config, error) {
    tlsConfig, ok := certCache.Load(host)
    if ok {
        return tlsConfig.(*tls.Config), nil
    }

    // Generate new server cert
    serverCert, err := utils.GenerateServerCert(host)
    if err != nil {
        return nil, err
    }

    tlsConfig = &tls.Config{
        Certificates: []tls.Certificate{*serverCert},
    }
    
    certCache.Store(host, tlsConfig)

    return tlsConfig.(*tls.Config), nil
}

func ForwardHTTPRequest(conn net.Conn, req *http.Request, ishttps bool) error {
	url := req.URL.String()
    if ishttps {
        url = "https://" + req.Host + req.URL.Path
    }
	headers := headersToMap(req.Header)
    httpMethod := req.Method
    var resp *http.Response
	var err error
	switch httpMethod {
    case "GET":
        resp, err = utils.Get(url,headers)
    case "HEAD":
        resp, err = utils.Head(url,headers)
    case "OPTIONS":
        resp, err = utils.Options(url,headers)
    case "TRACE":
        resp, err = utils.Trace(url,headers)
    case "POST":
        body, err := io.ReadAll(req.Body)
        if err != nil {
            return err
        }
        req.Body.Close()
        resp, err = utils.Post(url, body, headers)
    case "PUT":
        body, err := io.ReadAll(req.Body)
        if err != nil {
            return err
        }
        req.Body.Close()
        resp, err = utils.Put(url, body, headers)
    case "DELETE":
        body, err := io.ReadAll(req.Body)
        if err != nil {
            return err
        }
        req.Body.Close()
        resp, err = utils.Delete(url, body, headers)
    default:
        return fmt.Errorf("Not supported %s Method!", httpMethod)
    }
    if err != nil {
        return err
    }
	defer resp.Body.Close()
    body, err := io.ReadAll(resp.Body)
    if err != nil {
        return err
    }
    resp.Body = io.NopCloser(bytes.NewReader(body))
    responseDump, err := httputil.DumpResponse(resp, true)
    if err != nil {
        return err
    }
    _, err = conn.Write(responseDump)
    if err != nil {
        return err
    }
    MitmMatchFingerprint(url, resp.StatusCode, resp.Header, body)
    return nil
}

func MitmMatchFingerprint(url string, statuscode int, header http.Header, body []byte) {
    debody, err := DecodeBody(header.Get("Content-Encoding"), body)
    if err != nil {
        color.Red("[%s] [!] Error: %s", time.Now().Format("01-02 15:04:05"), err)
    }
    faviconurl := utils.FetchFavicon(debody)
    if strings.Contains(url, faviconurl) && statuscode == http.StatusOK {
        matchfingerprint(url, statuscode, nil, header, debody)
    } else {
        matchfingerprint(url, statuscode, debody, header, nil)
    }
}

func matchfingerprint(url string, statuscode int, body []byte, header http.Header, favicon []byte) {
    var matched bool
    cms := "None"
    server := header.Get("Server")
    if server == "" {
        server = "None"
    }
    title := utils.FetchTitle(body)
    if title == "" {
        title = "None"
    }
    for _, fingerprint := range config.Config.Finger {
        matched = matchKeywords(body, header, title, favicon, fingerprint)
        if matched {
            cms = fingerprint.CMS
            if _, loaded := matchedCMS.LoadOrStore(cms, true); !loaded {
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
    err := output.WriteOutputs()
    if err != nil {
        color.Red("[%s] [!] Error: %s", time.Now().Format("01-02 15:04:05"), err)
    }
}

func DecodeBody(contentEncoding string, body []byte) ([]byte, error) {
    var reader io.ReadCloser
    var err error

    switch strings.ToLower(contentEncoding) {
    case "gzip":
        reader, err = gzip.NewReader(bytes.NewReader(body))
        if err != nil {
            return nil, err
        }
    case "deflate":
        reader, err = zlib.NewReader(bytes.NewReader(body))
        if err != nil {
            return nil, err
        }
    case "identity", "":
        return body, nil
    default:
        return body, nil
    }

    defer reader.Close()
    decodedBody, err := io.ReadAll(reader)
    if err != nil {
        return nil, err
    }

    return decodedBody, nil
}

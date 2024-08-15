package models

import (
    "bufio"
    "bytes"
    "crypto/tls"
    "io"
    "io/ioutil"
    "net"
    "net/http"
    "net/http/httputil"
    "time"
    "strings"
    "compress/gzip"
    "compress/zlib"

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

        go func(conn net.Conn) {
            defer conn.Close()
            handleConnection(conn)
        }(conn)
    }
}

// handleConnection
func handleConnection(conn net.Conn) {
    defer conn.Close()
    reader := bufio.NewReader(conn)

    // Read HTTP Request
    req, err := http.ReadRequest(reader)
    if err != nil {
        color.Red("[%s] [!] Error: %v", time.Now().Format("01-02 15:04:05"), err)
        return
    }

    if req.Method == "CONNECT" {
        if err := handleHTTPS(conn, req); err != nil {
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
    case "HEAD":
        resp, err = utils.Head(url,headers)
        if err != nil {
            return err
        }
    case "OPTIONS":
        resp, err = utils.Options(url,headers)
        if err != nil {
            return err
        }
    case "TRACE":
        resp, err = utils.Trace(url,headers)
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
    case "DELETE":
        body, err := io.ReadAll(req.Body)
        if err != nil {
            return err
        }
        req.Body.Close()
        resp, err = utils.Delete(url,body,headers)
        if err != nil {
            return err
        }
    default:
        color.Red("[%s] [!] Error: Not supported %s Method!", time.Now().Format("01-02 15:04:05"), httpMethod)
        return nil
    }
    defer resp.Body.Close()
    body, err := io.ReadAll(resp.Body)
    if err != nil {
        return err
    }
    resp.Body = ioutil.NopCloser(bytes.NewReader(body))
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

// handleHTTPS
func handleHTTPS(conn net.Conn, req *http.Request) error {
    defer conn.Close()
    host := req.URL.Host
    hostParts := strings.Split(host, ":")
    if len(hostParts) > 0 {
        host = hostParts[0]
    }
    // Generate server cert
    serverCert, err := utils.GenerateServerCert(host)
    if err != nil {
        return err
    }

    tlsConfig := &tls.Config{
        Certificates: []tls.Certificate{*serverCert},
    }
    
    var resp *http.Response
    baseurl := "https://" + req.Host
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
    case "HEAD":
        resp, err = utils.Head(url,headers)
        if err != nil {
            return err
        }
    case "OPTIONS":
        resp, err = utils.Options(url,headers)
        if err != nil {
            return err
        }
    case "TRACE":
        resp, err = utils.Trace(url,headers)
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
    case "DELETE":
        body, err := io.ReadAll(clientReq.Body)
        if err != nil {
            return err
        }
        clientReq.Body.Close()
        resp, err = utils.Delete(url,body,headers)
        if err != nil {
            return err
        }
    default:
        color.Red("[%s] [!] Error: Not supported %s Method!", time.Now().Format("01-02 15:04:05"), httpsMethod)
        return nil
    }
    defer resp.Body.Close()
    body, err := io.ReadAll(resp.Body)
    if err != nil {
        return err
    }
    resp.Body = ioutil.NopCloser(bytes.NewReader(body))
    responseDump, err := httputil.DumpResponse(resp, true)
    if err != nil {
        return err
    }
    _, err = tlsConn.Write(responseDump)
    if err != nil {
        return err
    }
    MitmMatchFingerprint(url, resp.StatusCode,resp.Header, body)
    return nil
}

func MitmMatchFingerprint(url string, statuscode int, header http.Header, body []byte) {
    var matched bool
    cfg := config.GetConfig()
    server := header.Get("Server")
    if server == "" {
        server = "None"
    }
    cms := "None"
    title := utils.FetchTitle(body)
    if title == "" {
        title = "None"
    }
    debody, err := DecodeBody(header.Get("Content-Encoding"), body)
    if err != nil {
        color.Red("[%s] [!] Error: %s", time.Now().Format("01-02 15:04:05"), err)
    }
    faviconurl := utils.FetchFavicon(debody)
    if strings.Contains(url, faviconurl) && statuscode == http.StatusOK {
        for _, fingerprint := range cfg.Finger {
            matched = matchKeywords(nil, header, title, debody, fingerprint)
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
        err := output.WriteOutputs()
        if err != nil {
            color.Red("[%s] [!] Error: %s", time.Now().Format("01-02 15:04:05"), err)
        }
    } else {
        for _, fingerprint := range cfg.Finger {
            matched = matchKeywords(debody, header, title, nil, fingerprint)
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
        err := output.WriteOutputs()
        if err != nil {
            color.Red("[%s] [!] Error: %s", time.Now().Format("01-02 15:04:05"), err)
        }
    }
}

func DecodeBody(contentEncoding string, body []byte) ([]byte, error) {
    var reader io.ReadCloser
    var err error

    // 根据 content-encoding 创建相应的解码器
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
    decodedBody, err := ioutil.ReadAll(reader)
    if err != nil {
        return nil, err
    }

    return decodedBody, nil
}

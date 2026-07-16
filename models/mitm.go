package models

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"strings"
	"sync"

	"gitee.com/Trisia/gotlcp/tlcp"
	"golang.org/x/net/http2"

	"hfinger/config"
	"hfinger/logger"
	"hfinger/output"
	"hfinger/passive"
	"hfinger/rules"
	"hfinger/utils"
)

var (
	matchedCMS sync.Map
	certCache  = sync.Map{}
	h2Server   = &http2.Server{}
)

type proxyTLSConfig struct {
	std  *tls.Config
	tlcp *tlcp.Config
}

type negotiatedConn struct {
	net.Conn
	protocol string
}

func MitmServer(listenAddr string) {
	sem := make(chan struct{}, workerCount)

	if err := utils.EnsureCerts(); err != nil {
		logger.Error("Error: %v", err)
		return
	}

	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		logger.Error("Error: %v", err)
		return
	}
	defer listener.Close()

	logger.Info("Starting MITM Server at: %s", listenAddr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			logger.Error("Error: %v", err)
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

func handleConnection(conn net.Conn) {
	defer conn.Close()
	reader := bufio.NewReader(conn)

	req, err := http.ReadRequest(reader)
	if err != nil {
		logger.PrintByLevel(err, "")
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
		logger.PrintByLevel(err, "")
	}
}

func headersToMap(headers http.Header) map[string]string {
	headerMap := make(map[string]string)
	for key, values := range headers {
		if strings.EqualFold(key, "Proxy-Authorization") || strings.EqualFold(key, "Proxy-Connection") {
			continue
		}
		if len(values) > 0 {
			headerMap[key] = values[0]
		}
	}
	return headerMap
}

func requestTargetURL(req *http.Request, isHTTPS bool) string {
	if req == nil || req.URL == nil {
		return ""
	}
	if req.URL.IsAbs() {
		return req.URL.String()
	}

	scheme := "http"
	if isHTTPS {
		scheme = "https"
	}
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	path := req.URL.RequestURI()
	if path == "" {
		path = "/"
	}
	return scheme + "://" + host + path
}

func handleHTTP(conn net.Conn, req *http.Request) error {
	logger.Info("Received HTTP request: %s", requestTargetURL(req, false))
	err := ForwardHTTPRequest(conn, req, false)
	if err != nil {
		return err
	}
	return nil
}

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

	tlsConn, err := negotiateProxyTLS(conn, tlsConfig)
	if err != nil {
		return err
	}
	defer tlsConn.Close()

	// HTTP/2 连接处理
	switch tlsConn.protocol {
	case "h2":
		h2Server.ServeConn(tlsConn, &http2.ServeConnOpts{
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				handleHTTP2Request(w, r)
			}),
		})
		return nil
	default:
		reader := bufio.NewReader(tlsConn)
		clientReq, err := http.ReadRequest(reader)
		if err != nil {
			return err
		}
		logger.Info("[HTTPS] Received request: %s", "https://"+clientReq.Host+clientReq.URL.String())
		return ForwardHTTPRequest(tlsConn, clientReq, true)
	}
}

func getTLSConfigForHost(host string) (*proxyTLSConfig, error) {
	if tlsConfig, ok := certCache.Load(host); ok {
		return tlsConfig.(*proxyTLSConfig), nil
	}

	stdCert, err := utils.GenerateServerTLSCert(host)
	if err != nil {
		return nil, err
	}

	tlcpSignCert, tlcpEncCert, err := utils.GenerateServerTLCPCerts(host)
	if err != nil {
		return nil, err
	}

	tlsConfig := &proxyTLSConfig{
		std: &tls.Config{
			Certificates: []tls.Certificate{*stdCert},
			NextProtos:   []string{"h2", "http/1.1"},
		},
		tlcp: &tlcp.Config{
			Certificates: []tlcp.Certificate{*tlcpSignCert, *tlcpEncCert},
			NextProtos:   []string{"h2", "http/1.1"},
			CipherSuites: utils.SupportedTLCPCipherSuites(),
		},
	}

	// 原子操作存储配置
	actual, loaded := certCache.LoadOrStore(host, tlsConfig)
	if loaded {
		return actual.(*proxyTLSConfig), nil
	}

	return tlsConfig, nil
}

func negotiateProxyTLS(conn net.Conn, tlsConfig *proxyTLSConfig) (*negotiatedConn, error) {
	reader := bufio.NewReader(conn)
	header, err := reader.Peek(3)
	if err != nil {
		return nil, err
	}

	bufferedConn := &peekedConn{Conn: conn, reader: reader}
	switch header[1] {
	case 0x01:
		tlcpConn := tlcp.Server(bufferedConn, tlsConfig.tlcp)
		if err := tlcpConn.Handshake(); err != nil {
			return nil, err
		}
		return &negotiatedConn{Conn: tlcpConn, protocol: tlcpConn.ConnectionState().NegotiatedProtocol}, nil
	case 0x03:
		stdConn := tls.Server(bufferedConn, tlsConfig.std)
		if err := stdConn.Handshake(); err != nil {
			return nil, err
		}
		return &negotiatedConn{Conn: stdConn, protocol: stdConn.ConnectionState().NegotiatedProtocol}, nil
	default:
		return nil, fmt.Errorf("unsupported TLS/TLCP record version 0x%02x%02x", header[1], header[2])
	}
}

type peekedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (conn *peekedConn) Read(b []byte) (int, error) {
	if conn.reader.Buffered() > 0 {
		return conn.reader.Read(b)
	}
	return conn.Conn.Read(b)
}

func handleHTTP2Request(w http.ResponseWriter, r *http.Request) {
	fullURL := requestTargetURL(r, true)
	logger.Info("[HTTP2] Handling request: %s", fullURL)

	// 创建响应记录器
	recorder := httptest.NewRecorder()

	// 转发请求
	err := ForwardHTTP2Request(recorder, r)
	if err != nil {
		logger.PrintByLevel(err, fullURL)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// 复制响应到客户端
	for k, vv := range recorder.Header() {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(recorder.Code)
	if _, err := w.Write(recorder.Body.Bytes()); err != nil {
		logger.PrintByLevel(err, fullURL)
	}

	// 使用记录器中的数据安全地进行指纹匹配
	go MitmMatchFingerprint(fullURL, recorder.Code, recorder.Header(), recorder.Body.Bytes())
}

// 转发器：根据方法 + 参数 返回 *http.Response
type forwardFunc func(url string, headers map[string]string, body []byte) (*http.Response, error)

func forwardRequest(
	method string,
	url string,
	headers map[string]string,
	bodyNeeded bool,
	body io.ReadCloser,
	fwd forwardFunc,
) (*http.Response, error) {

	var bodyBytes []byte
	var err error
	if bodyNeeded && body != nil {
		bodyBytes, err = io.ReadAll(body)
		if err != nil {
			return nil, fmt.Errorf("read request body: %w", err)
		}
		body.Close()
	}

	switch method {
	case http.MethodGet:
		return fwd(url, headers, nil)
	case http.MethodHead:
		return fwd(url, headers, nil)
	case http.MethodOptions:
		return fwd(url, headers, nil)
	case http.MethodTrace:
		return fwd(url, headers, nil)
	case http.MethodPost, http.MethodPut, http.MethodDelete:
		return fwd(url, headers, bodyBytes)
	default:
		return nil, fmt.Errorf("unsupported method: %s", method)
	}
}

func ForwardHTTP2Request(w http.ResponseWriter, r *http.Request) error {
	url := requestTargetURL(r, true)
	headers := headersToMap(r.Header)

	resp, err := forwardRequest(
		r.Method,
		url,
		headers,
		r.Method == "POST" || r.Method == "PUT" || r.Method == "DELETE",
		r.Body,
		func(u string, h map[string]string, b []byte) (*http.Response, error) {
			switch r.Method {
			case "GET":
				return utils.Get(u, h)
			case "HEAD":
				return utils.Head(u, h)
			case "OPTIONS":
				return utils.Options(u, h)
			case "TRACE":
				return utils.Trace(u, h)
			case "POST":
				return utils.Post(u, b, h)
			case "PUT":
				return utils.Put(u, b, h)
			case "DELETE":
				return utils.Delete(u, b, h)
			default:
				return nil, fmt.Errorf("unsupported method: %s", r.Method)
			}
		},
	)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	for k, vv := range resp.Header {
		w.Header()[k] = vv
	}
	w.WriteHeader(resp.StatusCode)
	_, err = io.Copy(w, resp.Body)
	return err
}

func ForwardHTTPRequest(conn net.Conn, req *http.Request, ishttps bool) error {
	url := requestTargetURL(req, ishttps)
	headers := headersToMap(req.Header)

	resp, err := forwardRequest(
		req.Method,
		url,
		headers,
		req.Method == "POST" || req.Method == "PUT" || req.Method == "DELETE",
		req.Body,
		func(u string, h map[string]string, b []byte) (*http.Response, error) {
			switch req.Method {
			case "GET":
				return utils.Get(u, h)
			case "HEAD":
				return utils.Head(u, h)
			case "OPTIONS":
				return utils.Options(u, h)
			case "TRACE":
				return utils.Trace(u, h)
			case "POST":
				return utils.Post(u, b, h)
			case "PUT":
				return utils.Put(u, b, h)
			case "DELETE":
				return utils.Delete(u, b, h)
			default:
				return nil, fmt.Errorf("unsupported method: %s", req.Method)
			}
		},
	)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	contentType := resp.Header.Get("Content-Type")
	if isTextContent(contentType) {
		return handleTextResponse(conn, resp, url)
	}
	return handleBinaryResponse(conn, resp)
}

func handleTextResponse(conn net.Conn, resp *http.Response, url string) error {
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	clonedResp := *resp
	clonedResp.Body = io.NopCloser(bytes.NewReader(body))

	responseDump, err := httputil.DumpResponse(&clonedResp, true)
	if err != nil {
		return err
	}

	if _, err := conn.Write(responseDump); err != nil {
		return err
	}

	return MitmMatchFingerprint(url, resp.StatusCode, resp.Header, body)
}

func handleBinaryResponse(conn net.Conn, resp *http.Response) error {
	defer resp.Body.Close()
	return resp.Write(conn)
}

func isTextContent(contentType string) bool {
	if contentType == "" {
		return true
	}
	return strings.Contains(contentType, "text") ||
		strings.Contains(contentType, "json") ||
		strings.Contains(contentType, "xml") ||
		strings.Contains(contentType, "javascript") ||
		strings.Contains(contentType, "x-www-form-urlencoded")
}

func MitmMatchFingerprint(url string, statuscode int, header http.Header, body []byte) error {
	debody, err := DecodeBody(header.Get("Content-Encoding"), body)
	if err != nil {
		return err
	}
	faviconurl := utils.FetchFavicon(debody)
	if strings.Contains(url, faviconurl) && statuscode == http.StatusOK {
		matchfingerprint(url, statuscode, nil, header, debody)
	} else {
		matchfingerprint(url, statuscode, debody, header, nil)
	}
	return nil
}

func matchfingerprint(url string, statuscode int, body []byte, header http.Header, favicon []byte) {
	cms := "None"
	server := header.Get("Server")
	if server == "" {
		server = "None"
	}
	title := utils.FetchTitle(body)
	if title == "" {
		title = "None"
	}
	var newResults []config.Result
	response := rules.Response{
		ProbeID:    "passive",
		URL:        url,
		Path:       rules.PathFromURL(url),
		StatusCode: statuscode,
		Server:     server,
		Title:      title,
		Header:     header,
		Body:       body,
		Favicon:    favicon,
		Behavior: rules.BehaviorInfo{
			Compression: header.Get("Content-Encoding"),
			Allowed:     splitHeaderList(header.Get("Allow")),
			// 被动流量同样保留协议行为证据，确保 MITM 与主动扫描的规则能力一致。
			AltSvc: header.Get("Alt-Svc"),
			Cache:  cacheHeaderSummary(header),
		},
	}
	matches := rules.MatchRules([]rules.Response{response}, rules.ActiveRules())
	if honeypot := rules.AssessHoneypot(matches, []rules.Response{response}); honeypot.Matched {
		matches = append(matches, honeypot)
	}
	for _, match := range matches {
		cms = match.Rule.Name
		key := fmt.Sprintf("%s::%s", url, cms)
		if _, loaded := matchedCMS.LoadOrStore(key, true); !loaded {
			logger.Success("[%s] [%s] [%d] [%s] [%s] [Confidence %d%%]", url, cms, statuscode, server, title, match.Confidence)
			result := config.Result{
				URL:        url,
				CMS:        cms,
				Category:   match.Rule.Category,
				Version:    match.Version,
				Server:     server,
				StatusCode: statuscode,
				Title:      title,
				Confidence: match.Confidence,
				Evidence:   match.Evidence,
			}
			newResults = append(newResults, result)
		}
	}
	if len(newResults) > 0 {
		outputLock.Lock()
		defer outputLock.Unlock()

		for _, result := range newResults {
			output.AddResults(result)
			if err := passive.Append(result); err != nil {
				logger.Error("Error writing passive store: %s", err)
			}
		}

		if err := output.WriteOutputs(); err != nil {
			logger.Error("Error writing output: %s", err)
		}
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

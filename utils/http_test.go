package utils

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/tjfoc/gmsm/gmtls"
)

func TestGetBaseURL_BitsUT(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{
			name:  "https URL with path",
			input: "https://example.com/admin/login?next=/",
			want:  "https://example.com",
		},
		{
			name:  "http URL with port",
			input: "http://127.0.0.1:8080/index.html",
			want:  "http://127.0.0.1:8080",
		},
		{
			name:    "missing scheme",
			input:   "example.com",
			wantErr: true,
		},
		{
			name:    "unsupported scheme",
			input:   "ftp://example.com",
			wantErr: true,
		},
		{
			name:    "missing host",
			input:   "https:///path",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetBaseURL(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("GetBaseURL(%q) expected error", tt.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("GetBaseURL(%q) unexpected error: %v", tt.input, err)
			}
			if got != tt.want {
				t.Fatalf("GetBaseURL(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestExtractRedirectURL_BitsUT(t *testing.T) {
	tests := []struct {
		name   string
		header http.Header
		body   string
		want   string
	}{
		{
			name:   "location header wins",
			header: http.Header{"Location": []string{"/login"}},
			body:   `<meta http-equiv="refresh" content="0;url=/meta">`,
			want:   "/login",
		},
		{
			name:   "refresh header is case insensitive",
			header: http.Header{"Refresh": []string{"0; URL=/from-header"}},
			want:   "/from-header",
		},
		{
			name: "meta refresh double quoted content",
			body: `<html><head><meta http-equiv="refresh" content="0;url=/dashboard"></head></html>`,
			want: "/dashboard",
		},
		{
			name: "meta refresh single quoted content",
			body: `<meta http-equiv='refresh' content='0; URL=https://example.com/next'>`,
			want: "https://example.com/next",
		},
		{
			name: "noscript refresh is ignored",
			body: `<noscript><meta http-equiv="refresh" content="0;url=/ignored"></noscript>`,
			want: "",
		},
		{
			name: "javascript href redirect",
			body: `<script>window.location.href = "/js-next";</script>`,
			want: "/js-next",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{Header: tt.header}
			if resp.Header == nil {
				resp.Header = http.Header{}
			}
			got := ExtractRedirectURL(resp, []byte(tt.body))
			if got != tt.want {
				t.Fatalf("ExtractRedirectURL() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestExtractHTMLAttribute_BitsUT(t *testing.T) {
	tests := []struct {
		name string
		tag  string
		attr string
		want string
	}{
		{
			name: "double quoted attribute",
			tag:  `<meta content="0;url=/next" http-equiv="refresh">`,
			attr: "content",
			want: "0;url=/next",
		},
		{
			name: "single quoted mixed case attribute",
			tag:  `<meta CONTENT='0; URL=/next'>`,
			attr: "content",
			want: "0; URL=/next",
		},
		{
			name: "unquoted attribute",
			tag:  `<meta content=0;url=/next>`,
			attr: "content",
			want: "0;url=/next",
		},
		{
			name: "does not match partial attribute name",
			tag:  `<meta data-content="/wrong">`,
			attr: "content",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractHTMLAttribute([]byte(tt.tag), tt.attr)
			if got != tt.want {
				t.Fatalf("extractHTMLAttribute() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSetRequestHeaders_BitsUT(t *testing.T) {
	req, err := http.NewRequest(http.MethodPost, "https://example.com", bytes.NewBufferString("a=b"))
	if err != nil {
		t.Fatalf("NewRequest() unexpected error: %v", err)
	}

	setRequestHeaders(req, nil)

	if req.Header.Get("User-Agent") == "" {
		t.Fatalf("setRequestHeaders() did not set User-Agent")
	}
	if got := req.Header.Get("Content-Type"); got != "application/x-www-form-urlencoded; charset=UTF-8" {
		t.Fatalf("Content-Type = %q, want default form content type", got)
	}

	reqWithHeader, err := http.NewRequest(http.MethodPost, "https://example.com", bytes.NewBufferString("a=b"))
	if err != nil {
		t.Fatalf("NewRequest() unexpected error: %v", err)
	}
	setRequestHeaders(reqWithHeader, map[string]string{"content-type": "application/json"})

	if got := reqWithHeader.Header.Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q, want custom content type", got)
	}
}

func TestShouldFallbackToGMTLS(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "protocol version not supported",
			err:  fmt.Errorf("tls: protocol version not supported"),
			want: true,
		},
		{
			name: "handshake failure",
			err:  fmt.Errorf("remote error: tls: handshake failure"),
			want: true,
		},
		{
			name: "network error should not fallback",
			err:  fmt.Errorf("dial tcp 127.0.0.1:443: connect: connection refused"),
			want: false,
		},
		{
			name: "nil error",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shouldFallbackToGMTLS(tt.err); got != tt.want {
				t.Fatalf("shouldFallbackToGMTLS() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConfigureTLSMode(t *testing.T) {
	oldMode := tlsMode
	t.Cleanup(func() {
		tlsMode = oldMode
	})

	if err := ConfigureTLSMode(""); err != nil {
		t.Fatalf("ConfigureTLSMode(empty) unexpected error: %v", err)
	}
	if tlsMode != TLSModeAuto {
		t.Fatalf("tlsMode = %q, want auto", tlsMode)
	}

	for _, mode := range []string{TLSModeAuto, TLSModeGM, TLSModeStd} {
		if err := ConfigureTLSMode(mode); err != nil {
			t.Fatalf("ConfigureTLSMode(%q) unexpected error: %v", mode, err)
		}
		if tlsMode != mode {
			t.Fatalf("tlsMode = %q, want %q", tlsMode, mode)
		}
	}

	if err := ConfigureTLSMode("standard"); err == nil {
		t.Fatalf("ConfigureTLSMode() expected error for unsupported mode")
	}
}

func TestSupportedGMTLSCipherSuites(t *testing.T) {
	got := SupportedGMTLSCipherSuites()
	want := []uint16{gmtls.GMTLS_SM2_WITH_SM4_SM3, gmtls.GMTLS_ECDHE_SM2_WITH_SM4_SM3}
	if len(got) != len(want) {
		t.Fatalf("SupportedGMTLSCipherSuites() length = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("SupportedGMTLSCipherSuites()[%d] = %#x, want %#x", i, got[i], want[i])
		}
	}

	got[0] = 0
	if SupportedGMTLSCipherSuites()[0] == 0 {
		t.Fatalf("SupportedGMTLSCipherSuites() exposed mutable internal slice")
	}
}

func TestFormatGMTLSConnectErrorAddsCapabilityForUnsupportedStack(t *testing.T) {
	err := formatGMTLSConnectError(fmt.Errorf("tls: server selected unsupported protocol version 0x0303, while expecting 0x0101"))
	if err == nil {
		t.Fatalf("formatGMTLSConnectError() expected error")
	}
	if !strings.Contains(err.Error(), "unsupported GM/TLS version or cipher suite") {
		t.Fatalf("formatGMTLSConnectError() = %q, want unsupported stack guidance", err.Error())
	}
	if !strings.Contains(err.Error(), "GMTLS_SM2_WITH_SM4_SM3") || !strings.Contains(err.Error(), "GMTLS_ECDHE_SM2_WITH_SM4_SM3") {
		t.Fatalf("formatGMTLSConnectError() = %q, want supported cipher suites", err.Error())
	}
}

func TestActiveTLSConnectorGMModeUsesGMTLSOnly(t *testing.T) {
	connector := newActiveTLSConnector(TLSModeGM, nil, nil)
	stdCalls := 0
	gmCalls := 0
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()
	connector.stdDial = func(network, addr string, tlsConfig *tls.Config) (net.Conn, error) {
		stdCalls++
		return nil, fmt.Errorf("standard TLS should not be used")
	}
	connector.gmDial = func(network, addr string, tlsConfig *gmtls.Config) (net.Conn, error) {
		gmCalls++
		return clientConn, nil
	}

	conn, err := connector.Dial("tcp", "example.com:443")
	if err != nil {
		t.Fatalf("Dial() unexpected error: %v", err)
	}
	if conn == nil || stdCalls != 0 || gmCalls != 1 {
		t.Fatalf("Dial() stdCalls=%d gmCalls=%d conn=%v, want std=0 gm=1 conn", stdCalls, gmCalls, conn)
	}
}

func TestActiveTLSConnectorStdModeDoesNotFallback(t *testing.T) {
	connector := newActiveTLSConnector(TLSModeStd, nil, nil)
	stdErr := fmt.Errorf("remote error: tls: handshake failure")
	gmCalls := 0
	connector.stdDial = func(network, addr string, tlsConfig *tls.Config) (net.Conn, error) {
		return nil, stdErr
	}
	connector.gmDial = func(network, addr string, tlsConfig *gmtls.Config) (net.Conn, error) {
		gmCalls++
		return nil, nil
	}

	if _, err := connector.Dial("tcp", "example.com:443"); err != stdErr {
		t.Fatalf("Dial() error = %v, want original std error", err)
	}
	if gmCalls != 0 {
		t.Fatalf("Dial() gmCalls = %d, want 0", gmCalls)
	}
}

func TestActiveTLSConnectorAutoFallbacksForTLSHandshakeError(t *testing.T) {
	connector := newActiveTLSConnector(TLSModeAuto, nil, nil)
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()
	connector.stdDial = func(network, addr string, tlsConfig *tls.Config) (net.Conn, error) {
		return nil, fmt.Errorf("remote error: tls: handshake failure")
	}
	connector.gmDial = func(network, addr string, tlsConfig *gmtls.Config) (net.Conn, error) {
		return clientConn, nil
	}

	conn, err := connector.Dial("tcp", "example.com:443")
	if err != nil {
		t.Fatalf("Dial() unexpected error: %v", err)
	}
	if conn == nil {
		t.Fatalf("Dial() expected GM/TLS connection")
	}
}

func TestActiveTLSConnectorAutoKeepsStandardErrorWhenNoFallbackSignal(t *testing.T) {
	connector := newActiveTLSConnector(TLSModeAuto, nil, nil)
	stdErr := fmt.Errorf("dial tcp 127.0.0.1:443: connect: connection refused")
	gmCalls := 0
	connector.stdDial = func(network, addr string, tlsConfig *tls.Config) (net.Conn, error) {
		return nil, stdErr
	}
	connector.gmDial = func(network, addr string, tlsConfig *gmtls.Config) (net.Conn, error) {
		gmCalls++
		return nil, nil
	}

	if _, err := connector.Dial("tcp", "example.com:443"); err != stdErr {
		t.Fatalf("Dial() error = %v, want original std error", err)
	}
	if gmCalls != 0 {
		t.Fatalf("Dial() gmCalls = %d, want 0", gmCalls)
	}
}

func TestActiveTLSConnectorAutoReportsBothErrorsWhenFallbackFails(t *testing.T) {
	connector := newActiveTLSConnector(TLSModeAuto, nil, nil)
	connector.stdDial = func(network, addr string, tlsConfig *tls.Config) (net.Conn, error) {
		return nil, fmt.Errorf("remote error: tls: handshake failure")
	}
	connector.gmDial = func(network, addr string, tlsConfig *gmtls.Config) (net.Conn, error) {
		return nil, fmt.Errorf("gm failed")
	}

	_, err := connector.Dial("tcp", "example.com:443")
	if err == nil {
		t.Fatalf("Dial() expected error")
	}
	if !strings.Contains(err.Error(), "standard TLS failed") || !strings.Contains(err.Error(), "GM/TLS fallback failed") {
		t.Fatalf("Dial() error = %q, want both standard and GM/TLS errors", err.Error())
	}
}

func TestCreateHybridTransportProxyCredentialsDoNotMutateRequest(t *testing.T) {
	ConfigureClientCertificates("", "", "", "")
	ConfigureTLSMode(TLSModeAuto)
	t.Cleanup(func() {
		ConfigureClientCertificates("", "", "", "")
		ConfigureTLSMode(TLSModeAuto)
	})
	transport, err := createHybridTransport("http://user:pass@127.0.0.1:8080")
	if err != nil {
		t.Fatalf("createHybridTransport() unexpected error: %v", err)
	}
	if transport.Proxy == nil {
		t.Fatalf("createHybridTransport() did not configure proxy")
	}

	req, err := http.NewRequest(http.MethodGet, "https://example.com", nil)
	if err != nil {
		t.Fatalf("NewRequest() unexpected error: %v", err)
	}
	proxyURL, err := transport.Proxy(req)
	if err != nil {
		t.Fatalf("Proxy() unexpected error: %v", err)
	}
	if proxyURL == nil || proxyURL.User == nil {
		t.Fatalf("Proxy() did not preserve proxy credentials")
	}
	if got := req.Header.Get("Proxy-Authorization"); got != "" {
		t.Fatalf("Proxy() mutated request Proxy-Authorization header: %q", got)
	}
}

func TestCreateHybridTransportRequiresClientCertificatePairs(t *testing.T) {
	ConfigureClientCertificates("client.crt", "", "", "")
	t.Cleanup(func() {
		ConfigureClientCertificates("", "", "", "")
	})
	if _, err := createHybridTransport(""); err == nil {
		t.Fatalf("createHybridTransport() expected error for incomplete TLS client certificate pair")
	}

	ConfigureClientCertificates("", "", "gm-client.crt", "")
	if _, err := createHybridTransport(""); err == nil {
		t.Fatalf("createHybridTransport() expected error for incomplete GM/TLS client certificate pair")
	}
}

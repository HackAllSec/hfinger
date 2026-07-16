package models

import (
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"gitee.com/Trisia/gotlcp/tlcp"
	"hfinger/config"
	"hfinger/utils"
)

func TestRequestTargetURL(t *testing.T) {
	tests := []struct {
		name   string
		rawURL string
		host   string
		https  bool
		want   string
	}{
		{
			name:   "absolute proxy URL",
			rawURL: "http://example.com:8080/path?q=1",
			host:   "example.com:8080",
			want:   "http://example.com:8080/path?q=1",
		},
		{
			name:   "origin form HTTP URL",
			rawURL: "/path?q=1",
			host:   "example.com",
			want:   "http://example.com/path?q=1",
		},
		{
			name:   "origin form HTTPS URL",
			rawURL: "/secure",
			host:   "example.com",
			https:  true,
			want:   "https://example.com/secure",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, tt.rawURL, nil)
			if err != nil {
				t.Fatalf("NewRequest() error: %v", err)
			}
			req.Host = tt.host
			if got := requestTargetURL(req, tt.https); got != tt.want {
				t.Fatalf("requestTargetURL() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNegotiateProxyTLCPHandshake(t *testing.T) {
	certDir := t.TempDir()
	oldCertsDir := config.CertsDir
	oldCertsPath := config.CertsPath
	oldKeyPath := config.KeyPath
	oldGMCertsPath := config.GMCertsPath
	oldGMKeyPath := config.GMKeyPath
	config.CertsDir = certDir
	config.CertsPath = filepath.Join(certDir, config.CaCertFile)
	config.KeyPath = filepath.Join(certDir, config.CaKeyFile)
	config.GMCertsPath = filepath.Join(certDir, config.GMCaCertFile)
	config.GMKeyPath = filepath.Join(certDir, config.GMCaKeyFile)
	t.Cleanup(func() {
		config.CertsDir = oldCertsDir
		config.CertsPath = oldCertsPath
		config.KeyPath = oldKeyPath
		config.GMCertsPath = oldGMCertsPath
		config.GMKeyPath = oldGMKeyPath
	})

	if err := utils.EnsureCerts(); err != nil {
		t.Fatalf("EnsureCerts() unexpected error: %v", err)
	}
	tlsConfig, err := getTLSConfigForHost("example.com")
	if err != nil {
		t.Fatalf("getTLSConfigForHost() unexpected error: %v", err)
	}

	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()
	deadline := time.Now().Add(5 * time.Second)
	if err := serverConn.SetDeadline(deadline); err != nil {
		t.Fatalf("server SetDeadline() error: %v", err)
	}
	if err := clientConn.SetDeadline(deadline); err != nil {
		t.Fatalf("client SetDeadline() error: %v", err)
	}

	serverErr := make(chan error, 1)
	go func() {
		conn, err := negotiateProxyTLS(serverConn, tlsConfig)
		if err == nil {
			conn.Close()
		}
		serverErr <- err
	}()

	client := tlcp.Client(clientConn, &tlcp.Config{
		InsecureSkipVerify: true,
		CipherSuites:       utils.SupportedTLCPCipherSuites(),
	})
	if err := client.Handshake(); err != nil {
		t.Fatalf("TLCP client Handshake() error: %v", err)
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("negotiateProxyTLS() error: %v", err)
	}
}

func TestHeadersToMapStripsProxyHeaders(t *testing.T) {
	headers := http.Header{
		"User-Agent":          {"hfinger-test"},
		"Proxy-Authorization": {"Basic secret"},
		"Proxy-Connection":    {"keep-alive"},
	}

	got := headersToMap(headers)
	if got["User-Agent"] != "hfinger-test" {
		t.Fatalf("headersToMap() did not preserve normal header")
	}
	if _, ok := got["Proxy-Authorization"]; ok {
		t.Fatalf("headersToMap() leaked Proxy-Authorization")
	}
	if _, ok := got["Proxy-Connection"]; ok {
		t.Fatalf("headersToMap() leaked Proxy-Connection")
	}
}

func TestGetTLSConfigForHostUsesStandardTLSAndTLCP(t *testing.T) {
	certDir := t.TempDir()
	oldCertsDir := config.CertsDir
	oldCertsPath := config.CertsPath
	oldKeyPath := config.KeyPath
	oldGMCertsPath := config.GMCertsPath
	oldGMKeyPath := config.GMKeyPath
	config.CertsDir = certDir
	config.CertsPath = filepath.Join(certDir, config.CaCertFile)
	config.KeyPath = filepath.Join(certDir, config.CaKeyFile)
	config.GMCertsPath = filepath.Join(certDir, config.GMCaCertFile)
	config.GMKeyPath = filepath.Join(certDir, config.GMCaKeyFile)
	t.Cleanup(func() {
		config.CertsDir = oldCertsDir
		config.CertsPath = oldCertsPath
		config.KeyPath = oldKeyPath
		config.GMCertsPath = oldGMCertsPath
		config.GMKeyPath = oldGMKeyPath
	})

	if err := utils.EnsureCerts(); err != nil {
		t.Fatalf("EnsureCerts() unexpected error: %v", err)
	}

	tlsConfig, err := getTLSConfigForHost("example.com")
	if err != nil {
		t.Fatalf("getTLSConfigForHost() unexpected error: %v", err)
	}
	if tlsConfig.std == nil || len(tlsConfig.std.Certificates) != 1 {
		t.Fatalf("getTLSConfigForHost() did not configure standard TLS certificate")
	}
	if tlsConfig.tlcp == nil || len(tlsConfig.tlcp.Certificates) != 2 {
		t.Fatalf("getTLSConfigForHost() did not configure TLCP sign/encryption certificates")
	}
	wantSuites := utils.SupportedTLCPCipherSuites()
	if len(tlsConfig.tlcp.CipherSuites) != len(wantSuites) {
		t.Fatalf("CipherSuites length = %d, want %d", len(tlsConfig.tlcp.CipherSuites), len(wantSuites))
	}
	for i := range wantSuites {
		if tlsConfig.tlcp.CipherSuites[i] != wantSuites[i] {
			t.Fatalf("CipherSuites[%d] = %#x, want %#x", i, tlsConfig.tlcp.CipherSuites[i], wantSuites[i])
		}
	}
}

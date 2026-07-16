package models

import (
	"net/http"
	"path/filepath"
	"testing"

	"github.com/tjfoc/gmsm/gmtls"

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

func TestGetTLSConfigForHostUsesGMTLSAutoSwitch(t *testing.T) {
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
	if tlsConfig.GMSupport == nil || !tlsConfig.GMSupport.IsAutoSwitchMode() {
		t.Fatalf("getTLSConfigForHost() did not enable GM/TLS auto switch mode")
	}
	if tlsConfig.GetCertificate == nil || tlsConfig.GetKECertificate == nil {
		t.Fatalf("getTLSConfigForHost() did not configure GM sign/encryption certificates")
	}
	cert, err := tlsConfig.GetCertificate(&gmtls.ClientHelloInfo{
		SupportedVersions: []uint16{gmtls.VersionGMSSL},
	})
	if err != nil || cert == nil {
		t.Fatalf("GM GetCertificate() = %v, %v; want certificate", cert, err)
	}
}

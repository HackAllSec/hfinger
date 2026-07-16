package models

import (
	"crypto/tls"
	"net/http"
	"testing"
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

func TestIsGMClient(t *testing.T) {
	if !isGMClient(&tls.ClientHelloInfo{CipherSuites: []uint16{0xE011}}) {
		t.Fatalf("isGMClient() expected true for GM cipher suite")
	}
	if isGMClient(&tls.ClientHelloInfo{CipherSuites: []uint16{tls.TLS_AES_128_GCM_SHA256}}) {
		t.Fatalf("isGMClient() expected false for standard TLS cipher suite")
	}
}

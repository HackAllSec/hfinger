package utils

import (
	"bytes"
	"net/http"
	"testing"
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

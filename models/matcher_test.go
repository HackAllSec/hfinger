package models

import (
	"testing"

	"hfinger/config"
)

func TestMatchBody_BitsUT(t *testing.T) {
	body := []byte(`<html><script src="/static/app.js"></script><title>Admin</title></html>`)

	tests := []struct {
		name        string
		fingerprint config.Fingerprint
		want        bool
	}{
		{
			name: "and logic requires all rules",
			fingerprint: config.Fingerprint{
				Logic: "and",
				Rule:  []string{"/static/app.js", "<title>Admin</title>"},
			},
			want: true,
		},
		{
			name: "and logic fails when one rule is missing",
			fingerprint: config.Fingerprint{
				Logic: "and",
				Rule:  []string{"/static/app.js", "missing-token"},
			},
			want: false,
		},
		{
			name: "or logic succeeds when one rule matches",
			fingerprint: config.Fingerprint{
				Logic: "or",
				Rule:  []string{"missing-token", "/static/app.js"},
			},
			want: true,
		},
		{
			name: "unknown logic fails closed",
			fingerprint: config.Fingerprint{
				Logic: "xor",
				Rule:  []string{"/static/app.js"},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := matchBody(body, tt.fingerprint); got != tt.want {
				t.Fatalf("matchBody() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMatchHeader_BitsUT(t *testing.T) {
	header := map[string][]string{
		"Server":        {"cloudflare"},
		"X-Powered-By":  {"Express"},
		"Set-Cookie":    {"rememberMe=1"},
		"Cache-Control": {"max-age=0"},
	}

	tests := []struct {
		name        string
		fingerprint config.Fingerprint
		want        bool
	}{
		{
			name: "and logic can match across different headers",
			fingerprint: config.Fingerprint{
				Logic: "and",
				Rule:  []string{"Server", "Express"},
			},
			want: true,
		},
		{
			name: "or logic can match header value",
			fingerprint: config.Fingerprint{
				Logic: "or",
				Rule:  []string{"missing", "rememberMe=1"},
			},
			want: true,
		},
		{
			name: "or logic fails without match",
			fingerprint: config.Fingerprint{
				Logic: "or",
				Rule:  []string{"nginx", "PHP"},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := matchHeader(header, tt.fingerprint); got != tt.want {
				t.Fatalf("matchHeader() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMatchTitle_BitsUT(t *testing.T) {
	fingerprint := config.Fingerprint{
		Logic: "and",
		Rule:  []string{"Admin", "Portal"},
	}

	if !matchTitle("Admin Portal", fingerprint) {
		t.Fatalf("matchTitle() expected true")
	}
	if matchTitle("Admin Console", fingerprint) {
		t.Fatalf("matchTitle() expected false")
	}
}

func TestMatchKeywords_BitsUT(t *testing.T) {
	fingerprint := config.Fingerprint{
		Method:   "keyword",
		Location: "body",
		Logic:    "or",
		Rule:     []string{"Vite"},
	}

	if !matchKeywords([]byte("powered by Vite"), nil, "", nil, fingerprint) {
		t.Fatalf("matchKeywords() expected body keyword match")
	}

	fingerprint.Method = "unknown"
	if matchKeywords([]byte("powered by Vite"), nil, "", nil, fingerprint) {
		t.Fatalf("matchKeywords() expected unknown method to fail")
	}
}

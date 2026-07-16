package models

import "testing"

func TestTargetFromInputLine(t *testing.T) {
	tests := []struct {
		name string
		line string
		want string
	}{
		{
			name: "plain url",
			line: "https://example.com",
			want: "https://example.com",
		},
		{
			name: "httpx url jsonl",
			line: `{"url":"https://example.com","status_code":200}`,
			want: "https://example.com",
		},
		{
			name: "httpx input with scheme",
			line: `{"input":"example.com","scheme":"https","status_code":200}`,
			want: "https://example.com",
		},
		{
			name: "httpx host with scheme",
			line: `{"host":"192.0.2.10:8443","scheme":"https"}`,
			want: "https://192.0.2.10:8443",
		},
		{
			name: "invalid json falls back to raw line",
			line: `{"url":`,
			want: `{"url":`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := targetFromInputLine(tt.line); got != tt.want {
				t.Fatalf("targetFromInputLine() = %q, want %q", got, tt.want)
			}
		})
	}
}

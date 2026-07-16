package utils

import (
	"crypto/sha256"
	"fmt"
	"path/filepath"
	"testing"
)

func TestParseChecksum_BitsUT(t *testing.T) {
	hash := fmt.Sprintf("%x", sha256.Sum256([]byte("release-asset")))

	tests := []struct {
		name      string
		content   string
		assetName string
		want      string
		wantErr   bool
	}{
		{
			name:      "sha256sum file with matching asset",
			content:   "bad line\n" + hash + "  hfinger-darwin.zip\n",
			assetName: "hfinger-darwin.zip",
			want:      hash,
		},
		{
			name:      "single hash file",
			content:   hash + "\n",
			assetName: "hfinger-linux.zip",
			want:      hash,
		},
		{
			name:      "star-prefixed filename",
			content:   hash + " *hfinger-windows.zip\n",
			assetName: "hfinger-windows.zip",
			want:      hash,
		},
		{
			name:      "missing target asset",
			content:   hash + "  other.zip\n",
			assetName: "hfinger-linux.zip",
			wantErr:   true,
		},
		{
			name:      "invalid hash",
			content:   "not-a-sha256  hfinger.zip\n",
			assetName: "hfinger.zip",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseChecksum(tt.content, tt.assetName)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parseChecksum() expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("parseChecksum() unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("parseChecksum() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestIsSHA256Hex_BitsUT(t *testing.T) {
	valid := fmt.Sprintf("%x", sha256.Sum256([]byte("ok")))
	upper := ""
	for _, ch := range valid {
		if ch >= 'a' && ch <= 'f' {
			upper += string(ch - 'a' + 'A')
		} else {
			upper += string(ch)
		}
	}

	tests := []struct {
		name  string
		value string
		want  bool
	}{
		{name: "lowercase valid sha256", value: valid, want: true},
		{name: "uppercase valid sha256", value: upper, want: true},
		{name: "too short", value: valid[:63], want: false},
		{name: "non hex character", value: valid[:63] + "z", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isSHA256Hex(tt.value); got != tt.want {
				t.Fatalf("isSHA256Hex() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSafeZipPath_BitsUT(t *testing.T) {
	dest := t.TempDir()

	tests := []struct {
		name     string
		zipName  string
		wantOK   bool
		wantPath string
	}{
		{
			name:     "normal nested file",
			zipName:  "bin/hfinger",
			wantOK:   true,
			wantPath: filepath.Join(dest, "bin", "hfinger"),
		},
		{
			name:    "parent traversal is rejected",
			zipName: "../hfinger",
			wantOK:  false,
		},
		{
			name:    "nested parent traversal is rejected",
			zipName: "bin/../../hfinger",
			wantOK:  false,
		},
		{
			name:    "empty current path is rejected",
			zipName: ".",
			wantOK:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok, err := safeZipPath(dest, tt.zipName)
			if err != nil {
				t.Fatalf("safeZipPath() unexpected error: %v", err)
			}
			if ok != tt.wantOK {
				t.Fatalf("safeZipPath() ok = %v, want %v", ok, tt.wantOK)
			}
			if got != tt.wantPath {
				t.Fatalf("safeZipPath() path = %q, want %q", got, tt.wantPath)
			}
		})
	}
}

func TestSelectUpgradeAsset_BitsUT(t *testing.T) {
	assets := []GitHubReleaseAsset{
		{Name: "hfinger-darwin-arm64.zip.sha256", BrowserDownloadURL: "https://example.com/checksum"},
		{Name: "hfinger-linux-amd64.zip", BrowserDownloadURL: "https://example.com/linux"},
		{Name: "hfinger-darwin-arm64.zip", BrowserDownloadURL: "https://example.com/darwin"},
		{Name: "hfinger-windows-amd64.zip", BrowserDownloadURL: "https://example.com/windows"},
	}

	got, err := selectUpgradeAsset(assets, "darwin")
	if err != nil {
		t.Fatalf("selectUpgradeAsset() unexpected error: %v", err)
	}
	if got.Name != "hfinger-darwin-arm64.zip" {
		t.Fatalf("selectUpgradeAsset() = %q, want darwin zip asset", got.Name)
	}

	if _, err := selectUpgradeAsset(assets, "plan9"); err == nil {
		t.Fatalf("selectUpgradeAsset() expected unsupported OS error")
	}
}

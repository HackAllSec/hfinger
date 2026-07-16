package config

import (
	"path/filepath"

	"hfinger/rules"
)

// Result 存储指纹识别的结果
type Result struct {
	URL         string               `json:"url" xml:"URL"`
	CMS         string               `json:"cms" xml:"CMS"`
	Category    string               `json:"category,omitempty" xml:"Category,omitempty"`
	Version     string               `json:"version,omitempty" xml:"Version,omitempty"`
	Server      string               `json:"server" xml:"Server"`
	StatusCode  int                  `json:"statuscode" xml:"StatusCode"`
	Title       string               `json:"title" xml:"Title"`
	Confidence  int                  `json:"confidence,omitempty" xml:"Confidence,omitempty"`
	Evidence    []rules.Evidence     `json:"evidence,omitempty" xml:"Evidence>Item,omitempty"`
	DNS         *rules.DNSInfo       `json:"dns,omitempty" xml:"DNS,omitempty"`
	TLS         *rules.TLSInfo       `json:"tls,omitempty" xml:"TLS,omitempty"`
	Behavior    *rules.BehaviorInfo  `json:"behavior,omitempty" xml:"Behavior,omitempty"`
	Favicon     *rules.ResourceHash  `json:"favicon,omitempty" xml:"Favicon,omitempty"`
	Scripts     []rules.ResourceHash `json:"scripts,omitempty" xml:"Scripts>Item,omitempty"`
	Stylesheets []rules.ResourceHash `json:"stylesheets,omitempty" xml:"Stylesheets>Item,omitempty"`
}

type LastResponse struct {
	StatusCode int
	Server     string
	Title      string
}

var (
	Version      = "v1.0.9"
	CertsDir     = "certs"
	CaCertFile   = "ca.crt"
	CaKeyFile    = "ca.key"
	GMCaCertFile = "gm_ca.crt"
	GMCaKeyFile  = "gm_ca.key"
	CertsPath    = filepath.Join(CertsDir, CaCertFile)
	KeyPath      = filepath.Join(CertsDir, CaKeyFile)
	GMCertsPath  = filepath.Join(CertsDir, GMCaCertFile)
	GMKeyPath    = filepath.Join(CertsDir, GMCaKeyFile)
	ReleaseUrl   = "https://api.github.com/repos/HackAllSec/hfinger/releases/latest"
)

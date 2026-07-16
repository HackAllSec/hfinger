package rules

import "net/http"

const (
	StrategyScore = "score"
	StrategyAny   = "any"
	StrategyAll   = "all"
)

type Library struct {
	Rules []Rule `yaml:"rules"`
}

type Rule struct {
	ID       string      `yaml:"id"`
	Name     string      `yaml:"name"`
	Category string      `yaml:"category"`
	Vendor   string      `yaml:"vendor,omitempty"`
	Priority int         `yaml:"priority,omitempty"`
	Tags     []string    `yaml:"tags,omitempty"`
	Match    MatchBlock  `yaml:"match"`
	Extract  []Extractor `yaml:"extract,omitempty"`
	Negative []Matcher   `yaml:"negative,omitempty"`
	Metadata Metadata    `yaml:"metadata,omitempty"`
	Examples Examples    `yaml:"examples,omitempty"`
}

type MatchBlock struct {
	Strategy  string    `yaml:"strategy,omitempty"`
	Threshold int       `yaml:"threshold,omitempty"`
	Probes    []Probe   `yaml:"probes,omitempty"`
	Matchers  []Matcher `yaml:"matchers,omitempty"`
}

type Probe struct {
	ID       string    `yaml:"id"`
	Request  Request   `yaml:"request,omitempty"`
	Matchers []Matcher `yaml:"matchers"`
}

type Request struct {
	Method          string            `yaml:"method,omitempty"`
	Path            string            `yaml:"path,omitempty"`
	Headers         map[string]string `yaml:"headers,omitempty"`
	Body            string            `yaml:"body,omitempty"`
	FollowRedirects *bool             `yaml:"follow_redirects,omitempty"`
	AllowStatus     []int             `yaml:"allow_status,omitempty"`
}

type Matcher struct {
	Type          string      `yaml:"type"`
	Key           string      `yaml:"key,omitempty"`
	Value         interface{} `yaml:"value,omitempty"`
	Values        []string    `yaml:"values,omitempty"`
	Weight        int         `yaml:"weight,omitempty"`
	Evidence      string      `yaml:"evidence,omitempty"`
	CaseSensitive *bool       `yaml:"case_sensitive,omitempty"`
	Reason        string      `yaml:"reason,omitempty"`
}

type Extractor struct {
	Name    string `yaml:"name"`
	Type    string `yaml:"type"`
	Key     string `yaml:"key,omitempty"`
	Regex   string `yaml:"regex"`
	Group   int    `yaml:"group,omitempty"`
	Message string `yaml:"message,omitempty"`
}

type Metadata struct {
	References  []string `yaml:"references,omitempty"`
	Confidence  string   `yaml:"confidence,omitempty"`
	UpdatedAt   string   `yaml:"updated_at,omitempty"`
	Maintainers []string `yaml:"maintainers,omitempty"`
	Notes       string   `yaml:"notes,omitempty"`
}

type Examples struct {
	Positive []Fixture `yaml:"positive,omitempty"`
	Negative []Fixture `yaml:"negative,omitempty"`
}

type Fixture struct {
	Name       string            `yaml:"name,omitempty"`
	URL        string            `yaml:"url,omitempty"`
	Path       string            `yaml:"path,omitempty"`
	StatusCode int               `yaml:"status_code,omitempty"`
	Server     string            `yaml:"server,omitempty"`
	Title      string            `yaml:"title,omitempty"`
	Headers    map[string]string `yaml:"headers,omitempty"`
	Body       string            `yaml:"body,omitempty"`
	TLS        TLSInfo           `yaml:"tls,omitempty"`
}

type Response struct {
	ProbeID    string
	URL        string
	Path       string
	StatusCode int
	Server     string
	Title      string
	Header     http.Header
	Body       []byte
	Favicon    []byte
	TLS        TLSInfo
}

type TLSInfo struct {
	Subject  string   `json:"subject,omitempty" yaml:"subject,omitempty"`
	Issuer   string   `json:"issuer,omitempty" yaml:"issuer,omitempty"`
	DNSNames []string `json:"dns_names,omitempty" yaml:"dns_names,omitempty"`
	ALPN     string   `json:"alpn,omitempty" yaml:"alpn,omitempty"`
}

type Evidence struct {
	Source       string `json:"source" xml:"Source"`
	MatcherType  string `json:"matcher_type" xml:"MatcherType"`
	Key          string `json:"key,omitempty" xml:"Key,omitempty"`
	MatchedValue string `json:"matched_value" xml:"MatchedValue"`
	Weight       int    `json:"weight" xml:"Weight"`
	Message      string `json:"message,omitempty" xml:"Message,omitempty"`
	ResponseURL  string `json:"response_url,omitempty" xml:"ResponseURL,omitempty"`
}

type MatchResult struct {
	Rule       Rule
	Matched    bool
	Score      int
	Confidence int
	Version    string
	Evidence   []Evidence
	Response   Response
	Excluded   bool
	ExcludeBy  []Evidence
}

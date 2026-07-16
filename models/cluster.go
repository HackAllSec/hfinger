package models

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"hfinger/config"
	"hfinger/rules"
)

type ClusterSummary struct {
	Key     string   `json:"key"`
	Count   int      `json:"count"`
	URLs    []string `json:"urls"`
	Reason  string   `json:"reason"`
	Product string   `json:"product,omitempty"`
}

func ClusterResults(path string, minSize int) ([]ClusterSummary, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	groups := map[string]*ClusterSummary{}
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 1024), 4*1024*1024)
	for scanner.Scan() {
		var result config.Result
		if err := json.Unmarshal(scanner.Bytes(), &result); err != nil {
			continue
		}
		key, reason := clusterKey(result)
		if key == "" {
			continue
		}
		group, ok := groups[key]
		if !ok {
			group = &ClusterSummary{Key: key, Reason: reason, Product: result.CMS}
			groups[key] = group
		}
		group.Count++
		group.URLs = append(group.URLs, result.URL)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	clusters := make([]ClusterSummary, 0, len(groups))
	for _, group := range groups {
		if group.Count >= minSize {
			sort.Strings(group.URLs)
			clusters = append(clusters, *group)
		}
	}
	sort.Slice(clusters, func(i, j int) bool {
		if clusters[i].Count == clusters[j].Count {
			return clusters[i].Key < clusters[j].Key
		}
		return clusters[i].Count > clusters[j].Count
	})
	return clusters, nil
}

func PrintClusters(clusters []ClusterSummary) {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	_ = encoder.Encode(clusters)
}

func clusterKey(result config.Result) (string, string) {
	parts := []string{
		strings.ToLower(result.CMS),
		strings.ToLower(result.Category),
		strings.ToLower(result.Server),
		strings.ToLower(result.Title),
	}
	if result.TLS != nil {
		parts = append(parts, strings.ToLower(result.TLS.Subject), strings.ToLower(result.TLS.Issuer), strings.ToLower(result.TLS.JA3S))
	}
	if result.DNS != nil {
		parts = append(parts, lowerJoin(result.DNS.EdgeNetworks), lowerJoin(result.DNS.CNAME))
	}
	if result.Favicon != nil {
		parts = append(parts, result.Favicon.SHA256)
	}
	parts = append(parts, resourceDigest(result.Scripts), resourceDigest(result.Stylesheets))
	raw := strings.Join(nonEmpty(parts), "|")
	if raw == "" {
		return "", ""
	}
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:12]), fmt.Sprintf("cms/server/title/tls/dns/resource similarity for %s", result.CMS)
}

func lowerJoin(values ...interface{}) string {
	var parts []string
	for _, value := range values {
		switch typed := value.(type) {
		case string:
			parts = append(parts, strings.ToLower(typed))
		case []string:
			for _, item := range typed {
				parts = append(parts, strings.ToLower(item))
			}
		}
	}
	return strings.Join(nonEmpty(parts), ",")
}

func resourceDigest(items []rules.ResourceHash) string {
	if len(items) == 0 {
		return ""
	}
	values := make([]string, 0, len(items))
	for _, item := range items {
		values = append(values, item.SHA256, item.SHA1, item.MD5)
	}
	values = nonEmpty(values)
	if len(values) == 0 {
		return ""
	}
	sort.Strings(values)
	sum := sha256.Sum256([]byte(strings.Join(values, ",")))
	return hex.EncodeToString(sum[:8])
}

func nonEmpty(values []string) []string {
	filtered := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" && value != "none" {
			filtered = append(filtered, value)
		}
	}
	return filtered
}

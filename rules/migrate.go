package rules

import "strings"

const migratedLegacyReference = "builtin:migrated-legacy-rule"

func NormalizeRules(ruleSet []Rule) []Rule {
	normalized := make([]Rule, 0, len(ruleSet))
	for _, rule := range ruleSet {
		normalized = append(normalized, NormalizeRule(rule))
	}
	return normalized
}

func NormalizeRule(rule Rule) Rule {
	if rule.Category == "" || rule.Category == "legacy" {
		rule.Category = inferCategory(rule)
	}
	if len(rule.Tags) == 0 {
		rule.Tags = inferTags(rule)
	}
	if len(rule.Metadata.References) == 0 {
		rule.Metadata.References = []string{migratedLegacyReference}
	}
	if rule.Metadata.Confidence == "" {
		rule.Metadata.Confidence = inferMetadataConfidence(rule)
	}
	rule.Match.Matchers = normalizeMatchers(rule.Match.Matchers, rule)
	for i := range rule.Match.Probes {
		rule.Match.Probes[i].Matchers = normalizeMatchers(rule.Match.Probes[i].Matchers, rule)
	}
	return rule
}

func normalizeMatchers(matchers []Matcher, rule Rule) []Matcher {
	normalized := make([]Matcher, 0, len(matchers))
	for _, matcher := range matchers {
		if matcher.Evidence == "" || matcher.Evidence == "legacy rule match" {
			matcher.Evidence = inferEvidenceMessage(rule, matcher)
		}
		normalized = append(normalized, matcher)
	}
	return normalized
}

func inferEvidenceMessage(rule Rule, matcher Matcher) string {
	source := strings.ToLower(strings.TrimSpace(matcher.Type))
	switch {
	case strings.Contains(source, "favicon"):
		return "Migrated favicon hash evidence for " + rule.Name
	case strings.Contains(source, "header") || strings.Contains(source, "cookie"):
		return "Migrated HTTP header evidence for " + rule.Name
	case strings.Contains(source, "title"):
		return "Migrated HTML title evidence for " + rule.Name
	case strings.Contains(source, "tls"):
		return "Migrated TLS certificate evidence for " + rule.Name
	case strings.Contains(source, "json"):
		return "Migrated JSON/API evidence for " + rule.Name
	case strings.Contains(source, "server.banner"):
		return "Migrated server banner evidence for " + rule.Name
	default:
		return "Migrated response body evidence for " + rule.Name
	}
}

func inferCategory(rule Rule) string {
	text := strings.ToLower(rule.Name + " " + strings.Join(rule.Tags, " "))
	switch {
	case containsAny(text, "waf", "web application firewall", "防火墙", "安全狗", "safedog", "fortiweb", "barracuda"):
		return "waf"
	case containsAny(text, "cdn", "cloudflare", "akamai", "fastly", "网宿", "加速乐"):
		return "cdn"
	case containsAny(text, "vpn", "ssl vpn", "sslvpn", "堡垒", "网关", "gateway"):
		return "security-device"
	case containsAny(text, "kubernetes", "consul", "nacos", "dubbo", "rabbitmq", "rocketmq", "kafka"):
		return "middleware"
	case containsAny(text, "jenkins", "gitlab", "nexus", "harbor", "sonarqube", "airflow", "xxl-job"):
		return "devops"
	case containsAny(text, "grafana", "prometheus", "alertmanager", "kibana", "flink", "spark"):
		return "observability"
	case containsAny(text, "elasticsearch", "redis", "mongo", "mysql", "phpmyadmin", "influx", "clickhouse", "druid"):
		return "database"
	case containsAny(text, "spring", "swagger", "openapi", "fastapi", "tomcat", "weblogic", "jboss", "wildfly", "shiro", "asp.net", "java"):
		return "framework"
	case containsAny(text, "oa", "协同", "e-cology", "eoffice", "致远", "泛微", "通达", "蓝凌", "用友", "金蝶"):
		return "oa"
	case containsAny(text, "cms", "wordpress", "joomla", "drupal", "dedecms", "pbootcms", "typecho"):
		return "cms"
	case containsAny(text, "camera", "nvr", "nas", "router", "switch", "iot", "摄像", "路由"):
		return "iot-device"
	case containsAny(text, "gradio", "streamlit", "jupyter", "ollama", "open webui", "dify"):
		return "ai-service"
	default:
		return "middleware"
	}
}

func inferTags(rule Rule) []string {
	tags := []string{"migrated"}
	category := rule.Category
	if category == "" || category == "legacy" {
		category = inferCategory(rule)
	}
	tags = append(tags, category)
	if rule.Vendor != "" {
		tags = append(tags, strings.ToLower(strings.ReplaceAll(rule.Vendor, " ", "-")))
	}
	return tags
}

func inferMetadataConfidence(rule Rule) string {
	strong := 0
	for _, matcher := range collectMatchers(rule) {
		matcherType := strings.ToLower(strings.TrimSpace(matcher.Type))
		switch matcherType {
		case "favicon.hash", "header.contains", "header.regex", "cookie.contains", "json.key.exists", "json.path.eq", "tls.cert.subject.contains", "tls.cert.issuer.contains", "tls.cert.dns.contains":
			strong++
		}
	}
	if strong > 0 {
		return "medium"
	}
	return "low"
}

func containsAny(value string, needles ...string) bool {
	for _, needle := range needles {
		if strings.Contains(value, needle) {
			return true
		}
	}
	return false
}

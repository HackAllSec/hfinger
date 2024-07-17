package models

import (
    "strings"
    "strconv"

    "hfinger/config"
)

// matchKeywords 根据规则进行匹配
func matchKeywords(body []byte, header map[string][]string, title string, favicon []byte, fingerprint config.Fingerprint) bool {
    switch fingerprint.Method {
    case "keyword":
        switch fingerprint.Location {
        case "body":
            return matchBody(body, fingerprint)
        case "header":
            return matchHeader(header, fingerprint)
        case "title":
            return matchTitle(title, fingerprint)
        }
    case "faviconhash":
        if favicon != nil {
            icon_hash := Mmh3Hash32(StandBase64(favicon))
            for _, rule := range fingerprint.Rule {
                intrule,_ := strconv.ParseInt(rule, 10, 32)
                if icon_hash == int32(intrule) {
                    return true
                }
            }
        }
        return false
    }
    return false
}

// matchBody 根据规则匹配 body
func matchBody(body []byte, fingerprint config.Fingerprint) bool {
    bodyStr := string(body)
    switch fingerprint.Logic {
    case "and":
        for _, rule := range fingerprint.Rule {
            if !strings.Contains(bodyStr, rule) {
                return false
            }
        }
        return true
    case "or":
        for _, rule := range fingerprint.Rule {
            if strings.Contains(bodyStr, rule) {
                return true
            }
        }
        return false
    }
    return false
}

// matchHeader 根据规则匹配 header
func matchHeader(header map[string][]string, fingerprint config.Fingerprint) bool {
    switch fingerprint.Logic {
    case "and":
        for _, rule := range fingerprint.Rule {
            matched := false
            for key, values := range header {
                if strings.Contains(key, rule) {
                    matched = true
                    break
                }
                for _, value := range values {
                    if strings.Contains(value, rule) {
                        matched = true
                        break
                    }
                }
            }
            if !matched {
                return false
            }
        }
        return true
    case "or":
        for _, rule := range fingerprint.Rule {
            for key, values := range header {
                if strings.Contains(key, rule) {
                    return true
                }
                for _, value := range values {
                    if strings.Contains(value, rule) {
                        return true
                    }
                }
            }
        }
        return false
    }
    return false
}

// matchTitle 根据规则匹配 title
func matchTitle(title string, fingerprint config.Fingerprint) bool {
    switch fingerprint.Logic {
    case "and":
        for _, rule := range fingerprint.Rule {
            if !strings.Contains(title, rule) {
                return false
            }
        }
        return true
    case "or":
        for _, rule := range fingerprint.Rule {
            if strings.Contains(title, rule) {
                return true
            }
        }
        return false
    }
    return false
}

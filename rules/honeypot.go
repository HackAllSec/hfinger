package rules

import "fmt"

func AssessHoneypot(matches []MatchResult, responses []Response) MatchResult {
	// 蜜罐识别分两层：明确产品规则负责确定性命中，本函数只输出可疑度提示。
	// 因此阈值保持偏保守，避免把正常复杂站点直接标成蜜罐。
	result := MatchResult{
		Rule: Rule{
			ID:       "builtin-honeypot-suspicion",
			Name:     "Potential Honeypot",
			Category: "honeypot",
			Metadata: Metadata{Confidence: "medium"},
		},
	}

	products := make(map[string]struct{})
	categories := make(map[string]struct{})
	for _, match := range matches {
		if !match.Matched || match.Rule.Category == "honeypot" {
			continue
		}
		products[match.Rule.Name] = struct{}{}
		categories[match.Rule.Category] = struct{}{}
	}
	score := 0
	if len(products) >= 6 {
		score += 40
		result.Evidence = append(result.Evidence, Evidence{
			Source:       "honeypot.heuristic",
			MatcherType:  "product.conflict",
			MatchedValue: fmt.Sprintf("%d products matched", len(products)),
			Weight:       40,
			Message:      "多个产品同时命中，存在诱捕或伪装服务嫌疑",
		})
	}
	if len(categories) >= 4 {
		score += 30
		result.Evidence = append(result.Evidence, Evidence{
			Source:       "honeypot.heuristic",
			MatcherType:  "category.conflict",
			MatchedValue: fmt.Sprintf("%d categories matched", len(categories)),
			Weight:       30,
			Message:      "多个互斥技术栈分类同时命中，存在蜜罐嫌疑",
		})
	}

	ok2xx := 0
	for _, response := range responses {
		if response.StatusCode >= 200 && response.StatusCode < 300 {
			ok2xx++
		}
	}
	// 大量主动探测路径都返回 2xx，是 Web 蜜罐和万能路由的常见诱捕行为。
	if len(responses) >= 5 && ok2xx*100/len(responses) >= 80 {
		score += 30
		result.Evidence = append(result.Evidence, Evidence{
			Source:       "honeypot.heuristic",
			MatcherType:  "response.behavior",
			MatchedValue: fmt.Sprintf("%d/%d responses are 2xx", ok2xx, len(responses)),
			Weight:       30,
			Message:      "多数探测路径返回成功状态，需人工确认是否为万能响应或蜜罐",
		})
	}

	result.Score = score
	result.Confidence = min(100, score)
	result.Matched = score >= 60
	if result.Matched && len(responses) > 0 {
		result.Response = responses[0]
	}
	return result
}

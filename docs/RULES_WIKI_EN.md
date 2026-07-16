# HFinger Rules Wiki

This document explains how to write external YAML fingerprint rules for HFinger.

HFinger ships with built-in core rules. User and community rules should be written in YAML and loaded with `--rules`.

## 1. Quick Start

Create a rule file:

```yaml
id: example-admin
name: Example Admin
category: web

match:
  strategy: score
  threshold: 80
  probes:
    - id: homepage
      request:
        method: GET
        path: /
      matchers:
        - type: title.contains
          value: Example Admin
          weight: 50
          evidence: Page title matched
        - type: header.contains
          key: Set-Cookie
          value: example_session
          weight: 40
          evidence: Cookie fingerprint matched

metadata:
  references:
    - https://example.com

examples:
  positive:
    - name: homepage matched
      url: https://example.com/
      status_code: 200
      title: Example Admin
      headers:
        Set-Cookie: example_session=abc
      body: "<html><title>Example Admin</title></html>"
  negative:
    - name: similar page
      status_code: 200
      body: "<html><title>Other Admin</title></html>"
```

Validate the rule:

```bash
hfinger rules lint ./example-admin.yaml
```

If your IDE supports JSON Schema, associate `schemas/rule.schema.json` with HFinger `*.yaml` rule files to catch field, matcher type, and structure errors earlier.

Use the rule:

```bash
hfinger -u https://www.example.com --rules ./example-admin.yaml
```

## 2. Rule Structure

A rule describes one server-side product or component.

```yaml
id: unique-rule-id
name: Product Name
category: web
vendor: Vendor Name
priority: 80
tags:
  - tag1
  - tag2

match:
  strategy: score
  threshold: 80
  probes:
    - id: homepage
      request:
        method: GET
        path: /
      matchers:
        - type: body.contains
          value: unique-keyword
          weight: 80

negative:
  - type: body.contains
    value: false-positive-keyword
    reason: Avoid false positives

metadata:
  references:
    - https://example.com
  confidence: high
  updated_at: 2026-07-15
```

## 3. Top-Level Fields

| Field | Required | Description |
|-|-|-|
| `id` | Yes | Unique rule ID. Use lowercase letters, numbers, and hyphens. |
| `name` | Yes | Product or component name |
| `category` | Yes | Category such as `web`, `cms`, `middleware`, `waf`, `cdn`, `gateway` |
| `vendor` | No | Vendor name |
| `priority` | No | Priority for future conflict resolution |
| `tags` | No | Tags |
| `match` | Yes | Positive match rules |
| `negative` | No | Negative rules to reduce false positives |
| `metadata` | No | References and maintenance metadata |
| `examples` | No | Positive and negative examples for `hfinger rules test` replay |

## 4. Match Strategy

`match.strategy` supports:

| Strategy | Description |
|-|-|
| `score` | Accumulates matcher weights and matches when the score reaches `threshold` |
| `any` | Matches when any matcher matches |
| `all` | Matches only when all matchers match |

Prefer `score` for multi-evidence fingerprinting.

Example:

```yaml
match:
  strategy: score
  threshold: 70
```

## 5. Probe

A probe describes one HTTP request.

```yaml
probes:
  - id: login
    request:
      method: GET
      path: /login
    matchers:
      - type: status.eq
        value: 200
        weight: 20
```

Active mode automatically requests `request.path` values declared by rules.

## 6. Matcher

A matcher is one concrete match condition.

Common fields:

| Field | Required | Description |
|-|-|-|
| `type` | Yes | Matcher type |
| `key` | No | Header or cookie field name |
| `value` | No | One match value |
| `values` | No | Multiple match values |
| `weight` | No | Score weight. Default is 100 |
| `evidence` | No | Evidence message |
| `case_sensitive` | No | Whether matching is case-sensitive. Default is true |

## 7. Supported Matcher Types

| Type | Description |
|-|-|
| `body.contains` | Response body contains a string |
| `body.regex` | Response body matches a regex |
| `header.contains` | Header name or value contains a string |
| `header.regex` | Header matches a regex |
| `title.contains` | Page title contains a string |
| `title.regex` | Page title matches a regex |
| `cookie.contains` | `Set-Cookie` contains a string |
| `status.eq` | Status code equals a value |
| `status.in` | Status code is in a list |
| `favicon.hash` | Favicon mmh3 hash matches |
| `favicon.hash.md5` | Favicon MD5 hash matches |
| `favicon.hash.sha1` | Favicon SHA1 hash matches |
| `favicon.hash.sha256` | Favicon SHA256 hash matches |
| `path.exists` | Probed path returns 2xx/3xx |
| `redirect.to` | `Location` header contains a value |
| `script.src.contains` | Script src contains a value |
| `script.hash.md5` | External JavaScript content MD5 hash matches |
| `script.hash.sha1` | External JavaScript content SHA1 hash matches |
| `script.hash.sha256` | External JavaScript content SHA256 hash matches |
| `stylesheet.hash.md5` | External stylesheet/CSS content MD5 hash matches |
| `stylesheet.hash.sha1` | External stylesheet/CSS content SHA1 hash matches |
| `stylesheet.hash.sha256` | External stylesheet/CSS content SHA256 hash matches |
| `html.meta.contains` | Meta tag contains a value |
| `html.selector.exists` | HTML DOM selector exists |
| `json.key.exists` | JSON response contains a key |
| `json.path.eq` | JSON dotted path equals a value |
| `server.banner.contains` | Server banner contains a value |
| `server.banner.regex` | Server banner matches a regex |
| `tls.cert.subject.contains` | TLS certificate Subject contains a value |
| `tls.cert.issuer.contains` | TLS certificate Issuer contains a value |
| `tls.cert.dns.contains` | TLS certificate DNSNames contains a value |
| `tls.alpn.contains` | TLS ALPN contains a value |
| `tls.version.contains` | TLS version contains a value, such as `TLS1.3` |
| `tls.cipher.contains` | TLS Cipher Suite contains a value |
| `tls.ja3s.hash` | JA3S hash matches, preferring raw ServerHello extension sequence |
| `tls.ja3s.raw.contains` | JA3S raw string contains a value, such as `771,4865,43-51` |
| `dns.cname.contains` | DNS CNAME contains a value, useful for CDN/WAF identification |
| `dns.ns.contains` | DNS NS record contains a value, useful for authoritative DNS/CDN identification |
| `dns.txt.contains` | DNS TXT record contains a value |
| `dns.ip.contains` | DNS resolved IP contains a value |
| `dns.edge.contains` | DNS resolved IP matches a built-in CDN/edge network range |
| `http.version.contains` | HTTP protocol version contains a value, such as `HTTP/2` |
| `http.method.allowed` | `OPTIONS` response `Allow` methods contain a value |
| `http.alt_svc.contains` | `Alt-Svc` contains a value, useful for HTTP/3/QUIC hints |
| `http.quic.version.contains` | QUIC Version Negotiation response contains a version |
| `response.compression.contains` | `Content-Encoding` contains a value |
| `response.cache.contains` | CDN/cache response-header summary contains a value |
| `response.behavior.contains` | Advanced response behavior signals contain a value, such as `universal-route-suspected` |
| `response.etag.exists` | Response has an `ETag` header |
| `response.accept_ranges.exists` | Response has an `Accept-Ranges` header |

Note: `tls.ja3s.hash` prefers a raw TCP ClientHello probe that parses ServerHello version, Cipher Suite, and extension type sequence into a standard JA3S-shaped hash. If the raw probe fails, HFinger falls back to a stable summary from TLS version, Cipher Suite, and ALPN exposed by Go's standard library.

## 8. Negative Rules

`negative` reduces false positives. If any negative matcher matches, the rule is excluded.

```yaml
negative:
  - type: header.contains
    key: Server
    value: openresty
    reason: Avoid confusing OpenResty with Nginx
```

## 9. Authoring Suggestions

Recommended priority:

1. Prefer strong evidence such as unique headers, cookies, fixed asset paths, and API error shapes
2. Then use stable HTML, JS/CSS paths, default APIs, and default error pages
3. Use titles, common keywords, and favicon hashes carefully
4. Add `negative` matchers for rules prone to false positives
5. Provide `metadata.references` whenever possible

## 10. Rule Quality Check

```bash
hfinger rules lint ./rules/
hfinger rules test ./rules/
```

`rules lint` checks schema issues, invalid matchers, empty values, duplicate IDs, weak rules, missing strong evidence, missing references, and missing negative matchers.

`rules test` replays `examples.positive` and `examples.negative`:

- Positive examples must match the rule
- Negative examples must not match the rule

### JSON/API Rule Example

```yaml
id: example-api-gateway
name: Example API Gateway
category: gateway
match:
  strategy: score
  threshold: 80
  probes:
    - id: api_error
      request:
        method: GET
        path: /api/not-exists
      matchers:
        - type: json.key.exists
          value: request_id
          weight: 40
        - type: json.path.eq
          key: error.code
          value: UNAUTHORIZED
          weight: 40
examples:
  positive:
    - name: gateway error shape
      status_code: 401
      body: '{"error":{"code":"UNAUTHORIZED"},"request_id":"abc"}'
  negative:
    - name: generic json
      status_code: 200
      body: '{"message":"ok"}'
```

### TLS Rule Example

```yaml
id: example-tls-service
name: Example TLS Service
category: tls
match:
  strategy: any
  matchers:
    - type: tls.cert.issuer.contains
      value: Example CA
    - type: tls.alpn.contains
      value: h2
examples:
  positive:
    - name: TLS sample
      tls:
        issuer: CN=Example CA
        alpn: h2
```

### Middleware Header Rule Example

```yaml
id: example-middleware
name: Example Middleware
category: middleware
match:
  strategy: score
  threshold: 80
  matchers:
    - type: header.contains
      key: X-Powered-By
      value: Example Middleware
      weight: 50
      evidence: X-Powered-By exposes the middleware name
    - type: server.banner.regex
      value: (?i)example-middleware/[0-9.]+
      weight: 40
      evidence: Server banner exposes the middleware version
negative:
  - type: body.contains
    value: Example Middleware Documentation
    reason: Exclude documentation pages
examples:
  positive:
    - name: header matched
      status_code: 200
      server: Example-Middleware/1.2.3
      headers:
        X-Powered-By: Example Middleware
  negative:
    - name: documentation page
      status_code: 200
      body: Example Middleware Documentation
```

### WAF/CDN Rule Example

```yaml
id: example-waf
name: Example WAF
category: waf
match:
  strategy: score
  threshold: 70
  matchers:
    - type: header.contains
      key: Server
      value: ExampleWAF
      weight: 40
    - type: cookie.contains
      value: example_waf_session
      weight: 40
    - type: status.in
      values:
        - "403"
        - "406"
      weight: 20
examples:
  positive:
    - name: blocked response
      status_code: 403
      headers:
        Server: ExampleWAF
        Set-Cookie: example_waf_session=abc
```

### Fixed Path Probe Rule Example

```yaml
id: example-admin-path
name: Example Admin Path
category: web
match:
  strategy: score
  threshold: 80
  probes:
    - id: admin
      request:
        method: GET
        path: /example-admin/
      matchers:
        - type: path.exists
          weight: 30
          evidence: Default admin path exists
        - type: title.contains
          value: Example Admin
          weight: 50
          evidence: Default admin page title matched
negative:
  - type: status.eq
    value: 404
    reason: Probe path does not exist
```

### JavaScript Hash Rule Example

```yaml
id: example-js-hash
name: Example JS App
category: framework
match:
  strategy: score
  threshold: 80
  matchers:
    - type: script.src.contains
      value: /static/app.
      weight: 30
      evidence: Default frontend asset path is referenced
    - type: script.hash.sha256
      value: 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
      weight: 70
      evidence: External JavaScript content hash matched
```

### Honeypot Rule Example

```yaml
id: example-honeypot
name: Example Honeypot
category: honeypot
tags: [honeypot, deception]
match:
  strategy: score
  threshold: 100
  matchers:
    - type: title.contains
      value: Example Honeypot
      weight: 50
    - type: body.contains
      value: example-honeypot-marker
      weight: 50
negative:
  - type: body.contains
    value: Example Honeypot Documentation
    reason: Exclude product documentation pages
```

HFinger also includes heuristic honeypot assessment. If many mutually conflicting products/categories match, many active probe paths return 2xx, or many different paths return highly similar content, HFinger emits `Potential Honeypot` as a risk signal. Heuristic results assist manual judgment and do not replace explicit product rules.

## 11. LLM / Agent Integration

HFinger exposes a machine-readable capability manifest and JSONL output for LLM, agent, ASM, or SIEM pipelines:

```bash
hfinger llm manifest
hfinger llm skills
hfinger -f alive.jsonl --output-jsonl hfinger-results.jsonl
```

`hfinger llm skills` prints machine-readable playbooks for external agents, covering result triage, toolchain chaining, rule authoring, and honeypot review. Skills are user-side agent workflows, not part of HFinger's final decision path and not runtime directories that must be committed with the repository. LLM/Skill workflows are useful for target splitting, follow-up command generation, rule drafting, and low-impact review suggestions; they must not re-identify or invent fingerprints.

## 12. AI-Assisted Rule Drafting Prompt

AI can help draft candidate rules, but AI output should not be submitted as-is. Recommended workflow:

1. Ask AI to generate a YAML draft from response evidence
2. Manually verify matcher stability, uniqueness, and false-positive risk
3. Add positive and negative examples
4. Run `hfinger rules lint` and `hfinger rules test`

Prompt:

```text
You are an HFinger server-side fingerprint rule assistant. Generate a draft HFinger YAML rule from the HTTP/TLS evidence I provide.

Requirements:
1. Only fingerprint server-side products, web services, CMS products, backend frameworks, middleware, API gateways, WAF/CDN providers, load balancers, or protocol services.
2. Prefer stable strong evidence: unique headers, Set-Cookie values, Server banners, fixed asset paths, API JSON error shapes, TLS certificate Subject/Issuer/DNSNames, and status-code combinations.
3. Use titles, common body keywords, and favicon hashes carefully. If weak evidence is used, lower its weight and add negative matchers.
4. Use the score strategy with a reasonable threshold.
5. Include examples.positive and examples.negative.
6. Fill metadata.references with verifiable sources. If none are available, use an empty array and state that manual references are required.
7. Explain the evidence strength and false-positive risk of each matcher before the final YAML.
8. The final output must be valid HFinger YAML according to RULES_WIKI.

Evidence:
【Paste HTTP headers, status code, title, body summary, JSON error shape, TLS certificate info, favicon hash, etc.】
```

Chinese prompt:

```text
你是 HFinger 服务端指纹规则助手。请根据我提供的 HTTP/TLS 证据生成一条 HFinger YAML 指纹规则草案。

要求：
1. 只识别服务端产品、Web 服务、CMS、后端框架、中间件、API 网关、WAF/CDN、负载均衡或协议服务。
2. 优先使用稳定强证据：唯一 Header、Set-Cookie、Server banner、固定资源路径、API JSON 错误结构、TLS 证书 Subject/Issuer/DNSNames、状态码组合。
3. 谨慎使用页面标题、普通 body 关键词和 favicon hash；如果使用弱证据，必须降低 weight，并增加 negative。
4. 使用 score 策略，给出合理 threshold。
5. 输出 examples.positive 和 examples.negative。
6. metadata.references 必须填写可验证来源；没有来源时写空数组，并提醒需要人工补充。
7. 输出前解释每个 matcher 的证据强度和误报风险。
8. 最终只输出符合 HFinger RULES_WIKI 的 YAML。

证据如下：
【在这里粘贴 HTTP headers、status code、title、body 摘要、JSON 错误结构、TLS 证书信息、favicon hash 等】
```

## 13. FAQ

### Does HFinger support JSON rule files?

No. HFinger rules use YAML consistently. Built-in rule sources live under `rulesets/core/*.yaml`, and external rules also use YAML.

### Can external rules override built-in rules?

Yes. An external rule with the same `id` overrides the built-in rule. A different `id` adds a new rule.

### Can one file contain multiple rules?

Yes. Single-rule YAML and multi-rule YAML are both supported:

```yaml
rules:
  - id: app-a
    name: App A
    category: web
    match:
      strategy: any
      matchers:
        - type: body.contains
          value: App A
```

# HFinger 规则编写 Wiki

本文档介绍如何为 HFinger 编写外置 YAML 指纹规则。

HFinger 的核心规则已经内置到程序中。用户和社区新增规则建议使用 YAML 编写，并通过 `--rules` 加载。

## 1. 快速开始

创建规则文件：

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
          evidence: 页面标题命中
        - type: header.contains
          key: Set-Cookie
          value: example_session
          weight: 40
          evidence: Cookie 特征命中

metadata:
  references:
    - https://example.com

examples:
  positive:
    - name: 首页命中
      url: https://example.com/
      status_code: 200
      title: Example Admin
      headers:
        Set-Cookie: example_session=abc
      body: "<html><title>Example Admin</title></html>"
  negative:
    - name: 相似页面
      status_code: 200
      body: "<html><title>Other Admin</title></html>"
```

校验规则：

```bash
hfinger rules lint ./example-admin.yaml
```

使用规则：

```bash
hfinger -u https://www.example.com --rules ./example-admin.yaml
```

## 2. 规则文件结构

一条规则描述一个服务端产品或组件。

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
    reason: 排除误报

metadata:
  references:
    - https://example.com
  confidence: high
  updated_at: 2026-07-15
```

## 3. 顶层字段

| 字段 | 必填 | 说明 |
|-|-|-|
| `id` | 是 | 规则唯一 ID，建议使用小写字母、数字和中划线 |
| `name` | 是 | 产品或组件名称 |
| `category` | 是 | 产品类别，如 `web`、`cms`、`middleware`、`waf`、`cdn`、`gateway` |
| `vendor` | 否 | 厂商 |
| `priority` | 否 | 优先级，后续用于冲突裁决 |
| `tags` | 否 | 标签 |
| `match` | 是 | 正向匹配规则 |
| `negative` | 否 | 负向排除规则 |
| `metadata` | 否 | 参考链接、维护信息等 |
| `examples` | 否 | 正负样本，用于 `hfinger rules test` 回放 |

## 4. 匹配策略

`match.strategy` 支持：

| 策略 | 说明 |
|-|-|
| `score` | 按权重累计分数，达到 `threshold` 后命中 |
| `any` | 任意 matcher 命中即命中 |
| `all` | 所有 matcher 命中才命中 |

推荐优先使用 `score`，因为它更适合多证据融合。

示例：

```yaml
match:
  strategy: score
  threshold: 70
```

## 5. Probe

Probe 表示一次 HTTP 探测。

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

当前主动模式会自动请求规则中声明的 `request.path`。

## 6. Matcher

Matcher 是具体匹配条件。

通用字段：

| 字段 | 必填 | 说明 |
|-|-|-|
| `type` | 是 | matcher 类型 |
| `key` | 否 | Header/Cookie 等字段名 |
| `value` | 否 | 单个匹配值 |
| `values` | 否 | 多个匹配值 |
| `weight` | 否 | 权重，默认 100 |
| `evidence` | 否 | 命中证据说明 |
| `case_sensitive` | 否 | 是否大小写敏感，默认敏感 |

## 7. 支持的 Matcher 类型

| 类型 | 说明 |
|-|-|
| `body.contains` | 响应 body 包含字符串 |
| `body.regex` | 响应 body 命中正则 |
| `header.contains` | 响应 header 名或值包含字符串 |
| `header.regex` | 响应 header 命中正则 |
| `title.contains` | 页面标题包含字符串 |
| `cookie.contains` | `Set-Cookie` 包含字符串 |
| `status.eq` | 状态码等于指定值 |
| `status.in` | 状态码在指定列表中 |
| `favicon.hash` | favicon mmh3 hash 命中 |
| `path.exists` | 探测路径返回 2xx/3xx |
| `redirect.to` | `Location` header 包含指定值 |
| `script.src.contains` | script src 包含指定值 |
| `html.meta.contains` | meta 标签包含指定值 |
| `json.key.exists` | JSON 响应中存在指定 key |
| `json.path.eq` | JSON 点分路径等于指定值 |
| `server.banner.contains` | Server banner 包含指定值 |
| `server.banner.regex` | Server banner 命中正则 |
| `tls.cert.subject.contains` | TLS 证书 Subject 包含指定值 |
| `tls.cert.issuer.contains` | TLS 证书 Issuer 包含指定值 |
| `tls.cert.dns.contains` | TLS 证书 DNSNames 包含指定值 |
| `tls.alpn.contains` | TLS ALPN 包含指定值 |

## 8. Negative 规则

`negative` 用于降低误报。任意 negative 命中时，当前规则不会输出结果。

```yaml
negative:
  - type: header.contains
    key: Server
    value: openresty
    reason: 避免把 OpenResty 误报为 Nginx
```

## 9. 编写建议

优先级建议：

1. 优先使用唯一 Header、Cookie、固定资源路径、API 错误结构等强证据
2. 其次使用稳定 HTML、JS/CSS 路径、默认接口、默认错误页
3. 谨慎使用标题、普通关键词、favicon hash 等弱证据
4. 对容易误报的规则增加 `negative`
5. 尽量提供 `metadata.references`

## 10. 规则质量检查

```bash
hfinger rules lint ./rules/
hfinger rules test ./rules/
```

`rules lint` 会检查 schema、非法 matcher、空值、重复 ID、弱规则、缺少强证据、缺少 references、缺少 negative 等问题。

`rules test` 会执行 `examples.positive` 和 `examples.negative` 回放：

- positive 样本必须命中当前规则
- negative 样本不能命中当前规则

### JSON/API 规则示例

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
    - name: 网关错误结构
      status_code: 401
      body: '{"error":{"code":"UNAUTHORIZED"},"request_id":"abc"}'
  negative:
    - name: 普通 JSON
      status_code: 200
      body: '{"message":"ok"}'
```

### TLS 规则示例

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
    - name: TLS 样本
      tls:
        issuer: CN=Example CA
        alpn: h2
```

### 中间件 Header 规则示例

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
      evidence: X-Powered-By 暴露中间件名称
    - type: server.banner.regex
      value: (?i)example-middleware/[0-9.]+
      weight: 40
      evidence: Server banner 暴露中间件版本
negative:
  - type: body.contains
    value: Example Middleware Documentation
    reason: 排除普通文档页面
examples:
  positive:
    - name: Header 命中
      status_code: 200
      server: Example-Middleware/1.2.3
      headers:
        X-Powered-By: Example Middleware
  negative:
    - name: 文档页面
      status_code: 200
      body: Example Middleware Documentation
```

### WAF/CDN 规则示例

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
    - name: 拦截响应
      status_code: 403
      headers:
        Server: ExampleWAF
        Set-Cookie: example_waf_session=abc
```

### 固定路径探测规则示例

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
          evidence: 默认管理路径存在
        - type: title.contains
          value: Example Admin
          weight: 50
          evidence: 默认管理页面标题命中
negative:
  - type: status.eq
    value: 404
    reason: 探测路径不存在
```

## 11. AI 辅助生成规则提示词

AI 可以用于生成候选规则草案，但不建议直接把 AI 输出作为最终规则提交。推荐流程是：

1. 让 AI 基于响应证据生成 YAML 草案
2. 人工确认 matcher 是否稳定、唯一、低误报
3. 补充 positive / negative 样本
4. 执行 `hfinger rules lint` 和 `hfinger rules test`

可使用下面的提示词：

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

英文提示词：

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

## 12. 常见问题

### 是否还能使用旧 finger.json？

不能。新版本核心规则已经内置，外置规则使用 YAML。

### 外置规则会覆盖内置规则吗？

相同 `id` 的外置规则会覆盖内置规则。不同 `id` 会追加为新规则。

### 是否建议一个文件写多条规则？

可以。既支持单条规则，也支持：

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

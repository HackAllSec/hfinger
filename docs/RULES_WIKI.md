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

当前 `rules test` 会执行轻量规则校验。后续可扩展为 fixtures 正负样本回放。

## 11. 常见问题

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

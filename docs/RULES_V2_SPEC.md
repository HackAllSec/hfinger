# HFinger 规则库 V2 设计规范

## 1. 设计目标

规则库 V2 的目标是替代当前 `finger.json` 模型，使 HFinger 具备以下能力：

1. 表达更丰富的服务端指纹识别逻辑
2. 支持规则内置与外置 YAML 共存
3. 支持规则 lint / test / compile
4. 支持证据化输出与置信度评分
5. 支持社区贡献和后续长期维护

本规范不考虑兼容旧版 JSON 规则格式。

## 2. 当前规则模型的不足

当前规则只有 5 个字段：

- `cms`
- `method`
- `location`
- `logic`
- `rule`

存在以下限制：

1. 无法表达状态码、路径探测、Cookie、正则等能力
2. 无法表达负条件
3. 无法表达多探针组合
4. 无法表达证据和置信度
5. 无法表达规则元信息
6. 无法做高质量治理和测试

## 3. 规则体系总设计

规则体系分为两层：

### 3.1 规则源码层

使用 YAML 作为唯一人工维护格式。

作用：

- 社区贡献
- 规则审查
- 规则测试
- 规则治理

### 3.2 运行时规则层

程序运行时不直接依赖 YAML 文本进行匹配，而是加载编译后的内存结构。

运行时来源分为两部分：

1. 内置核心规则
2. 外置 YAML 规则编译后的动态加载结果

说明：

- 不再保留 `finger.json` 作为运行时依赖
- 不引入长期显式维护的公开 JSON 规则资产

## 4. 规则目录建议

```text
rules/
  web/
  cms/
  middleware/
  gateway/
  waf/
  cdn/
  loadbalancer/
  protocol/
  fixtures/
```

说明：

- `rules/*` 下放规则源码
- `fixtures/` 下放规则测试样本

## 5. 单条规则的数据模型

一条规则应代表一个“可识别产品”或“可识别服务端组件”，而不是单一关键词。

建议模型如下：

```yaml
id: nginx
name: Nginx
category: reverse-proxy
vendor: F5
priority: 90
tags:
  - http
  - reverse-proxy
  - load-balancer

match:
  strategy: score
  threshold: 60

  probes:
    - id: homepage
      request:
        method: GET
        path: /
      matchers:
        - type: header.contains
          key: Server
          value: nginx
          weight: 60
          evidence: Server header 命中
        - type: body.regex
          value: '(?i)welcome to nginx'
          weight: 40
          evidence: 默认欢迎页命中

negative:
  - type: header.contains
    key: Server
    value: openresty
    reason: 避免与 OpenResty 混淆

metadata:
  references:
    - https://nginx.org/
  confidence: high
  updated_at: 2026-07-15
```

## 6. 顶层字段规范

### 6.1 基础字段

- `id`: 规则唯一标识，稳定且不可重复
- `name`: 产品显示名称
- `category`: 类别
- `vendor`: 厂商
- `priority`: 冲突裁决优先级
- `tags`: 标签

### 6.2 match 字段

用于定义识别逻辑。

包含：

- `strategy`
- `threshold`
- `probes`

### 6.3 negative 字段

用于表达排除条件，降低误报。

### 6.4 metadata 字段

用于表达维护属性。

建议包含：

- `references`
- `confidence`
- `updated_at`
- `maintainers`
- `notes`

## 7. Probe 模型

Probe 表示一次探测行为。

示例：

```yaml
probes:
  - id: homepage
    request:
      method: GET
      path: /
```

后续支持的 request 字段建议包括：

- `method`
- `path`
- `headers`
- `body`
- `follow_redirects`
- `allow_status`

说明：

- 第一阶段只需支持 HTTP/HTTPS probe
- 后续可扩展 TLS、协议服务等 probe

## 8. Matcher 模型

Matcher 表示一个具体匹配条件。

建议字段：

- `type`
- `key`
- `value`
- `weight`
- `evidence`
- `case_sensitive`

## 9. 第一阶段必须支持的 Matcher

这是 V2 最小可用集合，也是对当前能力和竞品基线的追平集合。

### 9.1 文本类

- `body.contains`
- `body.regex`
- `header.contains`
- `header.regex`
- `title.contains`
- `cookie.contains`
- `script.src.contains`
- `html.meta.contains`

### 9.2 响应属性类

- `status.eq`
- `status.in`
- `redirect.to`

### 9.3 资源类

- `favicon.hash`
- `path.exists`

## 10. 第二阶段扩展 Matcher

这些能力不要求第一阶段一次完成，但规则结构必须预留。

- `json.key.exists`
- `json.path.eq`
- `xml.path.eq`
- `tls.cert.subject`
- `tls.cert.issuer`
- `tls.alpn.contains`
- `tls.jarm`
- `banner.contains`
- `server.product`
- `cdn.provider`
- `waf.provider`

## 11. 评分与命中策略

建议支持以下策略：

### 11.1 score 策略

适用于多证据综合判断。

规则：

- 每个 matcher 有 `weight`
- 命中后累计分数
- 达到 `threshold` 即判定命中

### 11.2 any 策略

任意一条命中即成立。

### 11.3 all 策略

全部命中才成立。

第一阶段建议主推 `score`，保留 `all/any` 作为语义补充。

## 12. Negative 规则

`negative` 用于显式排除误报。

行为建议：

- 任意 negative 命中时，当前规则直接失败
- negative 命中信息也应进入证据模型，方便解释“为何排除”

## 13. 证据模型

规则模型必须天然支持证据输出。

建议运行时证据结构：

```yaml
source: header
matcher_type: header.contains
key: Server
matched_value: nginx/1.24.0
weight: 60
message: Server header 命中
```

结果侧应至少输出：

- 命中来源
- 命中 matcher 类型
- 命中片段或摘要
- 贡献分值
- 最终置信度

## 14. 运行时内置策略

本次升级要求：

1. 将现有规则全部迁移到 V2
2. 在构建过程中将核心规则编译并内置到程序中
3. 默认运行时只依赖内置核心规则

后续补充策略：

1. 支持通过本地目录加载 YAML 自定义规则
2. 支持用户规则覆盖或补充核心规则

建议加载优先级：

1. 用户本地规则
2. 社区规则
3. 内置核心规则

## 15. 社区贡献要求

为了保证后续社区贡献质量，单条规则建议至少满足：

1. 具备唯一 `id`
2. 具备清晰 `category`
3. 至少包含 1 条强证据 matcher
4. 至少包含 1 个 `reference`
5. 尽量包含正样本 fixture
6. 高风险误报规则应包含 negative 条件

## 16. 配套命令建议

### 16.1 `hfinger rules lint`

检查：

- schema 合法性
- 非法字段
- 非法 matcher
- 重复 id
- 空规则
- 弱规则
- 缺少 reference

### 16.2 `hfinger rules test`

基于 fixtures 做正负样本回放。

### 16.3 `hfinger rules compile`

将 YAML 规则编译为内置或缓存格式。

### 16.4 `hfinger rules update`

更新社区规则包。

## 17. 与当前代码链路的关系

当前关键链路为：

```text
config.LoadFingerprintConfig
-> config.Config.Finger
-> models.matchKeywords
-> output.AddResults
```

V2 的目标替换链路为：

```text
rules.LoadBuiltins
-> rules.LoadExternalYAML
-> engine.RunProbes
-> engine.Match
-> engine.Score
-> output.WriteStructuredResults
```

这意味着：

- `config.Fingerprint` 将被新的规则结构替代
- `matchKeywords` 不再承担全部匹配职责
- 需要新增规则加载层、probe 层、matcher 层、scoring 层

## 18. 设计结论

规则库 V2 的核心结论如下：

1. 旧 `finger.json` 模型必须整体退出
2. YAML 成为唯一人工维护规则格式
3. 核心规则编译后内置进程序
4. 运行时通过统一规则模型执行匹配
5. 规则必须原生支持证据、评分、排除条件和测试

后续具体实施顺序见：

- `docs/IMPLEMENTATION_ROADMAP.md`

# HFinger

#### 简体中文 | [English](README_EN.md)

![logo](images/logo.png)

HFinger 是一个面向安全测试场景的服务端指纹识别工具，用于快速识别网站、Web 服务、CMS、后端框架、中间件、API 网关、WAF/CDN、负载均衡和常见服务端组件。

工具内置核心指纹规则，开箱即用；同时支持通过外置 YAML 规则扩展企业内部系统、社区规则和私有化产品识别能力。

当前内置指纹规则 **1621** 条，覆盖产品、Web 框架、CMS、中间件、CDN/WAF 等服务端组件 **1371** 种。

## 主要能力

- 服务端技术栈识别
- 主动模式和被动 MITM 模式
- 内置核心规则，无需依赖外部 `finger.json`
- 外置 YAML 规则加载
- Header、Body、Title、Cookie、Status、Redirect、Favicon 等多来源匹配
- Regex、路径探测、脚本资源、HTML Meta、JSON/API、TLS 证书和 Server banner 特征匹配
- 识别结果包含证据与置信度
- 支持 JSON、XML、XLSX 输出
- 支持被动模式 JSONL 结构化落盘与查询
- 支持 HTTP/1.1、HTTP/2
- 支持标准 HTTPS 和国密 HTTPS
- 支持代理、随机 UA、多线程
- 提供规则校验命令，方便维护自定义规则

## 项目结构

```text
.
├── cmd/                 命令行参数与子命令
├── config/              全局配置与结果结构
├── docs/                用户文档与规则 Wiki
├── icon_hash/           favicon hash 辅助工具
├── logger/              日志输出
├── models/              主动扫描与被动代理识别逻辑
├── output/              JSON、XML、XLSX 输出
├── rules/               内置规则、YAML 加载、规则校验与匹配引擎
├── utils/               HTTP、证书、升级等通用能力
├── README.md            中文说明文档
└── README_EN.md         英文说明文档
```

## 适用场景

- 红队打点阶段快速了解目标服务端技术栈
- 渗透测试前的信息收集
- 被动代理流量中的服务端组件识别
- 企业内部资产技术栈盘点
- 私有化产品或定制系统指纹规则维护

## 安装

```bash
git clone https://github.com/HackAllSec/hfinger.git
cd hfinger
go build
```

Windows 下可运行：

```bash
windows_build.bat
```

## 使用方法

### 单目标识别

```bash
hfinger -u https://www.example.com
```

### 从文件读取目标

```bash
hfinger -f targets.txt
```

目标文件每行一个 URL，建议包含协议，例如：

```text
https://www.example.com
http://192.168.1.10
```

### 指定代理

```bash
hfinger -u https://www.example.com -p http://127.0.0.1:8080
```

### 加载外置 YAML 规则

```bash
hfinger -u https://www.example.com --rules ./rules/custom.yaml
hfinger -f targets.txt --rules ./rules/community/
```

`--rules` 可以指定单个 YAML 文件，也可以指定目录，并且可以多次使用。

### 输出结果

```bash
hfinger -f targets.txt -j result.json
hfinger -f targets.txt -x result.xml
hfinger -f targets.txt -s result.xlsx
```

输出结果会包含命中产品、类别、状态码、Server、Title、置信度和证据。

### 被动模式

启动本地代理监听：

```bash
hfinger -l 127.0.0.1:8888 -s result.xlsx --passive-store passive.jsonl
```

浏览器或其它工具将代理设置为 `127.0.0.1:8888` 后，HFinger 会在转发流量的同时识别响应中的服务端指纹。

如需联动上游代理：

```bash
hfinger -l 127.0.0.1:8888 -p http://127.0.0.1:7777 -s result.xlsx --passive-store passive.jsonl
```

HTTPS 被动识别需要将 `certs` 目录下生成的证书导入浏览器或系统信任区。

查询被动模式 JSONL 结果：

```bash
hfinger passive query passive.jsonl
hfinger passive query passive.jsonl --cms Cloudflare --min-confidence 80
```

## 规则管理

HFinger 内置核心规则，不再依赖运行时 JSON 指纹文件。用户和社区规则使用 YAML 编写。

校验外置规则：

```bash
hfinger rules lint ./rules/custom.yaml
hfinger rules lint ./rules/community/
```

测试外置规则：

```bash
hfinger rules test ./rules/community/
```

`rules test` 支持规则内的正负样本回放，适合在提交社区规则前降低误报和漏报风险。

规则编写说明：

- [中文规则 Wiki](docs/RULES_WIKI.md)
- [English Rules Wiki](docs/RULES_WIKI_EN.md)

规则 Wiki 中提供了 AI 辅助生成规则草案的提示词模板。AI 输出仅建议作为草案，提交前仍需人工审核并通过 `rules lint/test`。

## YAML 规则示例

```yaml
id: example-admin
name: Example Admin
category: web
tags:
  - admin
  - example

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

negative:
  - type: body.contains
    value: unrelated product
    reason: 排除相似页面误报

metadata:
  references:
    - https://example.com
```

## 输出示例

```json
[
  {
    "url": "https://www.example.com",
    "cms": "Example Admin",
    "category": "web",
    "server": "nginx",
    "statuscode": 200,
    "title": "Example Admin",
    "confidence": 100,
    "evidence": [
      {
        "source": "title",
        "matcher_type": "title.contains",
        "matched_value": "Example Admin",
        "weight": 50,
        "message": "页面标题命中",
        "response_url": "https://www.example.com"
      }
    ]
  }
]
```

## 命令行参数

```text
-u, --url string           指定单个识别目标
-f, --file string          从文件读取目标
-l, --listen string        启动被动代理监听
-p, --proxy string         指定上游代理
-t, --thread int           指定线程数
-r, --redirect int         最大重定向次数
    --rules stringArray    加载外置 YAML 规则文件或目录
    --passive-store string 被动模式结果 JSONL 落盘路径
-j, --output-json string   输出 JSON 文件
-x, --output-xml string    输出 XML 文件
-s, --output-xlsx string   输出 XLSX 文件
-c, --check-update         检查工具更新
    --update               显示规则更新说明
    --upgrade              升级工具
-v, --version              显示版本
```

被动结果查询：

```text
hfinger passive query [jsonl-file]
    --url string             按 URL 片段过滤
    --cms string             按产品名过滤
    --category string        按类别过滤
    --min-confidence int     按最低置信度过滤
```

## 合法使用与免责声明

HFinger 仅用于获得授权的安全测试、资产识别、企业内部安全治理和研究学习。

此类工具具备批量探测和指纹识别能力，可能被滥用于未授权扫描。使用者必须确保自己对目标系统拥有明确授权，并遵守适用法律法规、合同约定和测试范围。

开发者不对任何未授权使用、攻击行为、数据泄露、业务中断或其它后果承担责任。使用本工具即表示你理解并接受上述限制。

## 贡献

欢迎提交 Issue、PR 和 YAML 指纹规则。提交规则前建议先运行：

```bash
hfinger rules lint ./rules/your-rule.yaml
hfinger rules test ./rules/your-rule.yaml
```

## 许可

请遵守 [MIT License](LICENSE)。

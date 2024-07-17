# HFinger

![](https://github.com/HackAllSec/hfinger/blob/main/images/logo.png)

**hfinger** 是一个**高性能**、**准确**的命令行指纹识别工具，用于红队打点时快速准确识别指定目标的 Web 框架和 CMS 等信息。受[EHole](https://github.com/EdgeSecurityTeam/EHole)启发开发此工具，它根据 `finger.json` 文件中定义的指纹进行匹配，优化原有文件结构，支持自定义匹配逻辑，支持关键词匹配和 favicon hash 匹配，并支持多线程和代理。

## 特性

- 高性能、准确的请求目标
- 根据响应 Header、body 和 title 与 finger.json 中定义的指纹进行匹配
- finger.json支持自定义匹配逻辑
- 支持多线程，线程数可通过 -t 参数调整
- 支持代理，通过 -p 参数指定代理
- 实时输出匹配结果，匹配到则使用绿色输出，未匹配到则使用白色输出
- 支持 JSON、XML 和 XLSX 格式的输出
- 由于Fofa的部分icon_hash和Mmh3Hash32的计算结果不一致，新增了icon_hash计算工具

## 使用方法

### 安装

确保你已经安装了 Go 语言环境，然后克隆本仓库并编译：
```bash
git clone https://github.com/HackAllSec/hfinger.git
cd hfinger
go build
```

### 命令行参数

```

 █████         ██████   ███
▒▒███         ███▒▒███ ▒▒▒
 ▒███████    ▒███ ▒▒▒  ████  ████████    ███████  ██████  ████████
 ▒███▒▒███  ███████   ▒▒███ ▒▒███▒▒███  ███▒▒███ ███▒▒███▒▒███▒▒███
 ▒███ ▒███ ▒▒▒███▒     ▒███  ▒███ ▒███ ▒███ ▒███▒███████  ▒███ ▒▒▒
 ▒███ ▒███   ▒███      ▒███  ▒███ ▒███ ▒███ ▒███▒███▒▒▒   ▒███
 ████ █████  █████     █████ ████ █████▒▒███████▒▒██████  █████
▒▒▒▒ ▒▒▒▒▒  ▒▒▒▒▒     ▒▒▒▒▒ ▒▒▒▒ ▒▒▒▒▒  ▒▒▒▒▒███ ▒▒▒▒▒▒  ▒▒▒▒▒
                                        ███ ▒███
                                       ▒▒██████
                                        ▒▒▒▒▒▒                     By:Hack All Sec

A high-performance command-line tool for web framework and CMS fingerprinting

Usage:
  hfinger [flags]

Flags:
  -f, --file string          Read assets from local files for fingerprint recognition, with one target per line
  -h, --help                 help for hfinger
  -j, --output-json string   Output all results to a JSON file
  -s, --output-xlsx string   Output all results to a Excel file
  -x, --output-xml string    Output all results to a XML file
  -p, --proxy string         Specify the proxy for accessing the target, supporting HTTP and SOCKS, example: http://127.0.0.1:8080
  -t, --thread int           Number of fingerprint recognition threads (default 100)
  -u, --url string           Specify the recognized target,example: https://www.example.com
```

### 使用示例

单个 URL 识别:
```bash
hfinger -u https://www.hackall.cn
```
从文件中读取目标并识别:
```bash
hfinger -f targets.txt
```
指定代理:
```bash
hfinger -u https://www.hackall.cn -p http://127.0.0.1:8080
```
输出为 JSON 格式:
```bash
hfinger -u https://www.hackall.cn -j output.json
```
输出为 XML 格式:
```bash
hfinger -u https://www.hackall.cn -x output.xml
```
输出为 XLSX 格式:
```bash
hfinger -u https://www.hackall.cn -s output.xlsx
```

### 输出示例

实时输出:
![](https://github.com/HackAllSec/hfinger/blob/main/images/output.png)
JSON 输出格式:
```json
[
  {
    "url": "https://example.com",
    "cms": "若依",
    "server": "cloudflare",
    "statuscode": 200,
    "title": "登录"
  },
  {
    "url": "https://example.com",
    "cms": "Shiro",
    "server": "cloudflare",
    "statuscode": 200,
    "title": "登录"
  }
]
```
XML 输出格式:
```
<results>
  <result>
    <URL>https://blog.hackall.cn</URL>
    <CMS>Typecho</CMS>
    <Server>cloudflare</Server>
    <StatusCode>404</StatusCode>
    <Title>Hack All Sec的博客 - Hack All Sec&#39;s Blog</Title>
  </result>
</results>
```
XLSX输出格式：
|URL|CMS|Server|StatusCode|Title|
|-|-|-|-|-|
|https://blog.hackall.cn|Typecho|cloudflare|200|Hack All Sec的博客 - Hack All Sec's Blog|

## 目录结构

```
hfinger/
|-- main.go               // 启动程序入口
|-- cmd/                  // 命令行相关代码
|   |-- banner.go
|   |-- args.go
|-- config/
|   |-- config.go         // 配置文件
|-- data/
|   |-- finger.json       // 指纹数据文件
|-- models/
|   |-- finger.go         // 核心指纹扫描逻辑
|   |-- faviconhash.go    // favicon hash计算
|   |-- matcher.go        // 匹配逻辑
|-- output
|   |-- jsonoutput.go     // 输出json文件
|   |-- xmloutput.go      // 输出xml文件
|   |-- xlsxoutput.go     // 输出xlsx文件
|-- utils/
|   |-- http.go           // HTTP请求相关
```

## 贡献

欢迎提交 PR 、Issues 和指纹库。

## 许可

MIT License

## HFinger简介

#### 简体中文 | [English](README_EN.md)
![](https://github.com/HackAllSec/hfinger/blob/main/images/logo.png)

**hfinger** 是一个**高性能**、**准确**的命令行指纹识别工具，用于红队打点时快速准确识别指定目标的 Web 框架、CDN 和 CMS 等信息。由于[EHole](https://github.com/EdgeSecurityTeam/EHole)很久没更新了，且存在一些缺点（误报、漏报、匹配不太灵活等），此工具根据 `finger.json` 文件中定义的指纹进行匹配，优化原有文件结构，增加匹配逻辑，增加错误页识别和被动识别模式。

虽然是重复造轮子了，但是造轮子的意义就在于优化和改进。后期会不断优化指纹库，认真做好每一个指纹。如果觉得不错的话，给个Star鼓励一下吧。

如何做好指纹，让匹配更精确？

1. 优先寻找独一无二的特征，如特定的响应Header，请求Header以及Cookie字段等
2. 其次寻找一般不变的数据，如网页中依赖的js文件，路径结构，body字段以及错误页面特征等
3. 实在找不到再寻找容易被修改的特征，如图标hash，网站标题等

最好结合起来，防止二次开发的系统修改图标、页面样式后无法匹配到。

### 特性

- 高性能、精准的识别目标
- 支持同一目标匹配多个框架指纹识别
- 支持主动模式和被动模式
- 支持根据错误页识别
- 根据响应 Header、body 和 title 与 finger.json 中定义的指纹进行匹配
- finger.json支持自定义匹配逻辑
- 支持随机UA头
- 支持多线程，线程数可通过 -t 参数调整
- 支持代理，通过 -p 参数指定代理
- 实时输出匹配结果，匹配到则使用绿色输出，未匹配到则使用白色输出
- 支持 JSON、XML 和 XLSX 格式的输出
- 由于Fofa的部分icon_hash和Mmh3Hash32的计算结果不一致，新增了icon_hash计算工具

### 指纹库

- 收录的产品、Web框架和CMS总数（根据不同cms的值统计，名称相同的指纹只记1次）：**1177**
- 指纹总数量（数量小的原因是已将指纹进行优化和合并，对同一资产的指纹进行合并）：**1412**
- 指纹库中的规则区分大小写，自定义添加指纹是需要注意

兵在精而不在多，指纹数量也一样，看数量意义不大，关键看可以识别的产品、Web框架和CMS数量。

#### 编写规则

指纹库位于 `data/finger.json`，格式为JSON。共包含5个字段：
- **cms**: 产品名称，包括 CMS 名称，CDN名称等
- **method**: 匹配方式，取值为 `keyword` 或 `faviconhash`，分别表示通过关键词匹配或通过网站图标 Hash 匹配，取值为 `faviconhash` 时会忽略 `location` 字段
- **location**: 匹配位置，取值为 `header`、`body`、`title`，分别表示匹配响应 Header、body 和 title 中的内容
- **logic**: 匹配逻辑，取值为 `and` 或 `or`，分别表示规则的 AND 和 OR 逻辑，匹配规则包含多个条件时生效
- **rule**: 匹配规则，包含多个条件，条件之间使用 `,` 分割

## 使用方法

### 安装

确保你已经安装了 Go 语言环境，然后克隆本仓库并编译：
```bash
git clone https://github.com/HackAllSec/hfinger.git
cd hfinger
go build
```

Windows下可直接运行`windows_build.bat`编译。

### 命令行参数

```bash

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
  -l, --listen string        Using a proxy resource collector to retrieve targets, example: 127.0.0.1:6789
  -j, --output-json string   Output all results to a JSON file
  -s, --output-xlsx string   Output all results to a Excel file
  -x, --output-xml string    Output all results to a XML file
  -p, --proxy string         Specify the proxy for accessing the target, supporting HTTP and SOCKS, example: http://127.0.0.1:8080
  -t, --thread int           Number of fingerprint recognition threads (default 100)
      --update               Update fingerprint database
      --upgrade              Upgrade to the latest version
  -u, --url string           Specify the recognized target,example: https://www.example.com
  -v, --version              Display the current version of the tool
```

### 使用示例

#### 主动模式

单个 URL 识别:
```bash
hfinger -u https://www.hackall.cn
```
从文件中读取目标并识别（每行一个url，需要添加协议，如http或https）:
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

#### 被动模式

用法和`Xray`类似，包括启动监听、添加上游代理，工具联动等等。被动模式可以识别主动模式无法识别的指纹，且比主动扫描更加全面。

启动监听即可：
```bash 
hfinger -l 127.0.0.1:8888 -s res.xlsx
```
![](https://github.com/HackAllSec/hfinger/blob/main/images/passivemode.png)
![](https://github.com/HackAllSec/hfinger/blob/main/images/passive.png)

要支持HTTPS需要将`certs`目录下的证书导入浏览器。

**联动其它工具**

联动`Xray`或其它工具有两种方式：

方式一:  `Target -> Xray/Burp -> hfinger`

在上边的基础上浏览器设置代理经过`Xray`或`Burp`，然后在`Xray`或`Burp`配置上游代理为`hfinger`的监听地址即可。

方式二: `Target -> hfinger -> Xray`

启动`hfinger`被动模式，使用`-p`参数设置上游代理，浏览器设置代理为`hfinger`的监听地址即可。
```bash
hfinger -l 127.0.0.1:8888 -p http://127.0.0.1:7777 -s res.xlsx
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

![](https://github.com/HackAllSec/hfinger/blob/main/images/xlsx.png)

## 目录结构

```
hfinger/
|-- main.go               // 启动程序入口
|-- cmd/                  // 命令行相关代码
|   |-- banner.go
|   |-- args.go
|-- icon                  // 图标文件
|-- config/
|   |-- config.go         // 配置文件
|-- data/
|   |-- finger.json       // 指纹数据文件
|-- models/
|   |-- finger.go         // 核心指纹扫描逻辑
|   |-- faviconhash.go    // favicon hash计算
|   |-- matcher.go        // 匹配逻辑
|   |-- mitm.go           // 中间人代理服务
|-- output
|   |-- jsonoutput.go     // 输出json文件
|   |-- xmloutput.go      // 输出xml文件
|   |-- xlsxoutput.go     // 输出xlsx文件
|-- utils/
|   |-- http.go           // HTTP请求相关
|   |-- certs.go          // 证书相关
|   |-- update.go         // 升级与更新
```

## 变更记录

[CHANGELOG](CHANGELOG.md)

## 贡献

欢迎提交 PR 、Issues 和指纹库。

欢迎基于此项目开发其它工具或扩展此工具功能。

你可以在`data/finger.json`文件末尾追加新的指纹，并通过PR提交。或提交Issues告诉我们不能识别的CMS或框架以及更多细节。

## 许可

请遵守[MIT License](LICENSE)

## Star History

![](https://api.star-history.com/svg?repos=HackAllSec/hfinger&type=Date)

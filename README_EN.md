## HFinger Introduction

#### English | [简体中文](README.md)
![](https://github.com/HackAllSec/hfinger/blob/main/images/logo.png)

**hfinger** is a high-performance and accurate command-line fingerprint recognition tool, It is used for fast and accurate identification of specified targets during Red Team RBI, including web frameworks, CDN, and CMS information. Since [EHole](https://github.com/EdgeSecurityTeam/EHole) has not been updated for a long time and has some shortcomings (false positives, false negatives, inflexible matching, etc.), this tool is based on the `finger.json` file Match the defined fingerprints, optimize the original file structure, add matching logic, and add error page recognition and passive recognition modes.
﻿
Although we are reinventing the wheel, the meaning of reinventing the wheel lies in optimization and improvement. In the future, we will continue to optimize the fingerprint database and carefully prepare each fingerprint. If you think it's good, give it a Star to encourage it.

How to prepare fingerprints to make matching more accurate?

1. Prioritize looking for unique features, such as specific response headers, request headers and cookie fields, etc.
2. Secondly, look for generally unchanged data, such as js files, path structures, body fields, error page characteristics, etc. that are dependent on the web page.
3. If you really can’t find it, look for features that can be easily modified, such as icon hash, website title, etc.

It is best to combine these methods to prevent secondary development systems from being unable to match the icons and page styles after modifying them.

### Characteristic

- High performance and accurate target recognition
- Supports fingerprint recognition of multiple frames matching the same target
- Support active mode and passive mode
- Support error page identification
- Match the response header, body and title against the fingerprint defined in finger.json
- finger.json supports custom matching logic
- Support random UA header
- Supports multi-threading, the number of threads can be adjusted through the -t parameter
- Support proxy, specify proxy through -p parameter
- Output the matching results in real time. If the match is matched, the green output will be used. If the match is not matched, the white output will be used.
- Supports output in JSON, XML and XLSX formats
- Due to inconsistent calculation results of some of Fofa's icon_hash and Mmh3Hash32, a new icon_hash calculation tool has been added

### Fingerprint database

- The total number of included products, web frameworks and CMS (based on the values ​​of different cms, fingerprints with the same name are only recorded once): **1177**
- The total number of fingerprints (the reason for the small number is that the fingerprints have been optimized and merged, and the fingerprints of the same asset have been merged): **1412**
- The rules in the fingerprint database are case-sensitive, and you need to pay attention to adding fingerprints by customization

The soldiers are not numerous but refined, the same goes for the number of fingerprints. The total number of fingerprints is little significance. The key is the number of products, web frameworks and CMS that can be identified.

#### Write rules

The fingerprint database is located in the `finger.json` file, and the format is JSON. There are 5 fields in total:
- **cms**: Product name, including CMS name, CDN name, etc
- **method**: The matching method, the value of `keyword` or `faviconhash`, which means that the match is made by keyword or faviconhash, respectively, and the `location` field is ignored when the value is `faviconhash`
- **location**: The matching position, with the values of `header`, `body`, and `title`, indicates the content in the header, body, and title of the matching response, respectively
- **logic**: The matching logic, with the value of `and` or `or`, represents the AND and OR logic of the rule, respectively, and takes effect when the matching rule contains multiple conditions
- **rule**: Matching rules, which contain multiple conditions, are split using `,` between conditions

## How to use

### Install

Make sure you have the Go language environment installed, then clone this repository and compile:
```bash
git clone https://github.com/HackAllSec/hfinger.git
cd hfinger
go build
```

Under Windows, you can directly run `windows_build.bat` to compile.

### Command line parameters

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

### Usage example

#### Active mode

Single URL identification:
```bash
hfinger -u https://www.hackall.cn
```
Read the target from the file and identify it (one url per line, you need to add the protocol, such as http or https):
```bash
hfinger -f targets.txt
```
Set proxy address:
```bash
hfinger -u https://www.hackall.cn -p http://127.0.0.1:8080
```
Output in JSON format:
```bash
hfinger -u https://www.hackall.cn -j output.json
```
Output in XML format:
```bash
hfinger -u https://www.hackall.cn -x output.xml
```
Output in XLSX format:
```bash
hfinger -u https://www.hackall.cn -s output.xlsx
```

#### Passive mode

Usage is similar to `Xray`, including starting monitoring, adding upstream agents, tool linkage, etc. Passive mode can identify fingerprints that active mode cannot and is more comprehensive than active scanning.

Just start monitoring：
```bash 
hfinger -l 127.0.0.1:8888 -s res.xlsx
```
![](https://github.com/HackAllSec/hfinger/blob/main/images/passivemode.png)
![](https://github.com/HackAllSec/hfinger/blob/main/images/passive.png)

To support HTTPS, you need to import the certificate in the `certs` directory into the browser.

**Combine with other tools**

There are two ways to combine `Xray` or other tools：

Method 1:  `Target -> Xray/Burp -> hfinger`

Based on the above, set the browser's proxy address to `Xray` or `Burp`, and then configure the upstream proxy in `Xray` or `Burp` to be the listening address of `hfinger`.

Method 2: `Target -> hfinger -> Xray`

Start `hfinger` passive mode, use the `-p` parameter to set the upstream proxy, and set the browser's proxy to the listening address of `hfinger`.
```bash
hfinger -l 127.0.0.1:8888 -p http://127.0.0.1:7777 -s res.xlsx
```

### Output example

real time output:

![](https://github.com/HackAllSec/hfinger/blob/main/images/output.png)

JSON output format:
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
XML output format:
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
XLSX output format：
|URL|CMS|Server|StatusCode|Title|
|-|-|-|-|-|
|https://blog.hackall.cn|Typecho|cloudflare|200|Hack All Sec的博客 - Hack All Sec's Blog|

![](https://github.com/HackAllSec/hfinger/blob/main/images/xlsx.png)

## Directory structure

```
hfinger/
|-- main.go               // Start program entry
|-- cmd/                  // Command line related code
|   |-- banner.go
|   |-- args.go
|-- icon                  // Icon files
|-- config/
|   |-- config.go         // Config file
|-- data/
|   |-- finger.json       // Fingerprint data file
|-- models/
|   |-- finger.go         // Core fingerprint scanning logic
|   |-- faviconhash.go    // favicon hash calculate
|   |-- matcher.go        // matching logic
|   |-- mitm.go           // MITM service
|-- output
|   |-- jsonoutput.go     // Output json file
|   |-- xmloutput.go      // Output xml file
|   |-- xlsxoutput.go     // Output xlsx file
|-- utils/
|   |-- http.go           // HTTP request
|   |-- certs.go          // Certs
|   |-- update.go         // Update and upgrade
```

## Change log

[CHANGELOG](CHANGELOG.md)

## Contribute

Submissions of PRs, Issues and Fingerprints are welcome.

You are welcome to develop other tools based on this project or extend the functionality of this tool.

You can append a new fingerprint to the end of the `data/finger.json` file and submit it via PR. Or submit Issues to tell us the unrecognized CMS or framework and more details.

## License

Please comply with [MIT License](LICENSE)

## Star History

![](https://api.star-history.com/svg?repos=HackAllSec/hfinger&type=Date)

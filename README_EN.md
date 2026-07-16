# HFinger

#### [简体中文](README.md) | English

![logo](images/logo.png)

HFinger is a server-side fingerprinting tool for security testing. It helps identify websites, web services, CMS products, backend frameworks, middleware, API gateways, WAF/CDN providers, load balancers, and common server-side components.

HFinger ships with built-in core fingerprint rules and works out of the box. It also supports external YAML rules for community contributions, private products, and internal enterprise systems.

The current build includes **1621** built-in fingerprint rules covering **1371** server-side products, web frameworks, CMS products, middleware, CDN/WAF providers, and related components.

## Features

- Server-side technology fingerprinting
- Active scanning and passive MITM mode
- Built-in core rules without runtime `finger.json` dependency
- External YAML rule loading
- Header, body, title, cookie, status, redirect, and favicon matching
- Regex, path probe, script source, and HTML meta matching
- Evidence and confidence in scan results
- JSON, XML, and XLSX output
- HTTP/1.1 and HTTP/2 support
- Standard HTTPS and GM/TLS HTTPS support
- Proxy, random User-Agent, and multithreading support
- Rule validation commands for custom rule maintenance

## Project Structure

```text
.
├── cmd/                 CLI flags and subcommands
├── config/              Global configuration and result structures
├── docs/                User documentation and rules wiki
├── icon_hash/           Favicon hash helper
├── logger/              Logging
├── models/              Active scanning and passive proxy fingerprinting
├── output/              JSON, XML, and XLSX output
├── rules/               Built-in rules, YAML loading, validation, and matching engine
├── utils/               HTTP, certificates, upgrade, and shared utilities
├── README.md            Chinese documentation
└── README_EN.md         English documentation
```

## Use Cases

- Understanding server-side technology stacks during reconnaissance
- Information gathering before penetration testing
- Passive fingerprinting from proxied traffic
- Internal asset technology inventory
- Maintaining fingerprints for private or customized products

## Installation

```bash
git clone https://github.com/HackAllSec/hfinger.git
cd hfinger
go build
```

On Windows:

```bash
windows_build.bat
```

## Usage

### Scan One Target

```bash
hfinger -u https://www.example.com
```

### Scan Targets From File

```bash
hfinger -f targets.txt
```

Use one URL per line. Including the scheme is recommended:

```text
https://www.example.com
http://192.168.1.10
```

### Use Proxy

```bash
hfinger -u https://www.example.com -p http://127.0.0.1:8080
```

### Load External YAML Rules

```bash
hfinger -u https://www.example.com --rules ./rules/custom.yaml
hfinger -f targets.txt --rules ./rules/community/
```

`--rules` accepts a YAML file or a directory and can be used multiple times.

### Write Output

```bash
hfinger -f targets.txt -j result.json
hfinger -f targets.txt -x result.xml
hfinger -f targets.txt -s result.xlsx
```

Results include product name, category, status code, Server header, title, confidence, and evidence.

### Passive Mode

Start a local proxy:

```bash
hfinger -l 127.0.0.1:8888 -s result.xlsx
```

Configure your browser or another tool to use `127.0.0.1:8888` as the proxy. HFinger forwards traffic and fingerprints server responses at the same time.

Use an upstream proxy:

```bash
hfinger -l 127.0.0.1:8888 -p http://127.0.0.1:7777 -s result.xlsx
```

For HTTPS passive fingerprinting, import the generated certificate under the `certs` directory into your browser or system trust store.

## Rule Management

HFinger uses built-in core rules and no longer depends on a runtime JSON fingerprint file. User and community rules are written in YAML.

Validate external rules:

```bash
hfinger rules lint ./rules/custom.yaml
hfinger rules lint ./rules/community/
```

Run lightweight rule tests:

```bash
hfinger rules test ./rules/community/
```

Rule authoring documentation:

- [中文规则 Wiki](docs/RULES_WIKI.md)
- [English Rules Wiki](docs/RULES_WIKI_EN.md)

## YAML Rule Example

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
          evidence: Page title matched
        - type: header.contains
          key: Set-Cookie
          value: example_session
          weight: 40
          evidence: Cookie fingerprint matched

negative:
  - type: body.contains
    value: unrelated product
    reason: Avoid false positives from similar pages

metadata:
  references:
    - https://example.com
```

## Output Example

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
        "message": "Page title matched",
        "response_url": "https://www.example.com"
      }
    ]
  }
]
```

## CLI Flags

```text
-u, --url string           Scan one target
-f, --file string          Read targets from file
-l, --listen string        Start passive proxy listener
-p, --proxy string         Use upstream proxy
-t, --thread int           Number of threads
-r, --redirect int         Max redirects
    --rules stringArray    Load external YAML rule file or directory
-j, --output-json string   Write JSON output
-x, --output-xml string    Write XML output
-s, --output-xlsx string   Write XLSX output
-c, --check-update         Check tool updates
    --update               Show rule update guidance
    --upgrade              Upgrade the tool
-v, --version              Show version
```

## Legal Use and Disclaimer

HFinger is intended only for authorized security testing, asset identification, internal security governance, and research.

Tools of this type can perform batch probing and fingerprinting, and may be abused for unauthorized scanning. You must ensure that you have explicit authorization for all targets and comply with applicable laws, contracts, and testing scopes.

The developers are not responsible for unauthorized use, attacks, data leakage, service disruption, or any other consequences. By using this tool, you acknowledge and accept these limitations.

## Contribution

Issues, pull requests, and YAML fingerprint rules are welcome. Before submitting rules, run:

```bash
hfinger rules lint ./rules/your-rule.yaml
hfinger rules test ./rules/your-rule.yaml
```

## License

See [MIT License](LICENSE).

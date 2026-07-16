# HFinger

#### [简体中文](README.md) | English

![logo](images/logo.png)

HFinger is a server-side fingerprinting tool for security testing. It helps identify websites, web services, CMS products, backend frameworks, middleware, API gateways, WAF/CDN providers, load balancers, and common server-side components.

HFinger ships with built-in core fingerprint rules and works out of the box. It also supports external YAML rules for community contributions, private products, and internal enterprise systems.

The current build includes **1621** built-in fingerprint rules covering **1371** server-side products, web frameworks, CMS products, middleware, CDN/WAF providers, and related components.

## Positioning

HFinger is not intended to replace vulnerability scanners. It is designed to be the server-side technology identification layer in a security testing workflow. It answers "what server-side components are behind this target" and returns evidence plus confidence so results can be reviewed, automated, and reused by downstream tools.

Compared with simple keyword-based fingerprinting, HFinger focuses on:

- Built-in core rules without shipping a runtime rule file
- External YAML rules for community and private rule maintenance
- Multi-source evidence across headers, body, cookies, favicon, JSON/API, TLS, and Server banners
- Evidence and confidence output for review and automation
- Both active scanning and passive proxy fingerprinting

## Features

- Server-side technology fingerprinting
- Active scanning and passive MITM mode
- Built-in core rules without runtime `finger.json` dependency
- External YAML rule loading
- Header, body, title, cookie, status, redirect, and favicon matching
- Regex, path probe, script source, HTML meta, JSON/API, TLS certificate, and Server banner matching
- Evidence and confidence in scan results
- JSON, XML, and XLSX output
- Passive mode JSONL persistence and query
- HTTP/1.1 and HTTP/2 support
- Active requests with standard TLS, GM/TLS fallback, and client-certificate authentication
- Passive MITM with adaptive standard TLS / GM/TLS handshakes
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
hfinger -l 127.0.0.1:8888 -s result.xlsx --passive-store passive.jsonl
```

Configure your browser or another tool to use `127.0.0.1:8888` as the proxy. HFinger forwards traffic and fingerprints server responses at the same time.

Use an upstream proxy:

```bash
hfinger -l 127.0.0.1:8888 -p http://127.0.0.1:7777 -s result.xlsx --passive-store passive.jsonl
```

For HTTPS passive fingerprinting, import the generated certificates under the `certs` directory into your browser or system trust store. Standard TLS clients should trust `ca.crt`, while GM/TLS clients should trust `gm_ca.crt`.

Note: passive mode uses an adaptive TLS/GM/TLS handshake. Standard TLS clients and GM/TLS clients are handled on the same listener and automatically select the matching handshake flow.

### Mutual TLS / GM/TLS

If a target requires a client certificate, provide the certificate and private key:

```bash
hfinger -u https://www.example.com --client-cert client.crt --client-key client.key
```

For GM/TLS targets, provide a GM client certificate explicitly:

```bash
hfinger -u https://www.example.com --gm-client-cert gm-client.crt --gm-client-key gm-client.key
```

When only `--client-cert/--client-key` is provided, HFinger uses it for standard TLS and also attempts to load it as a GM/TLS client certificate. If the GM/TLS client certificate is different, use `--gm-client-cert/--gm-client-key`.

### Active TLS Mode

Active requests use `auto` mode by default, so users do not need to specify an extra option. `auto` tries standard TLS first. If standard TLS fails with a GM/TLS-like error, HFinger automatically tries GM/TLS fallback.

If the target type is already known, force the mode explicitly:

```bash
# GM/TLS only
hfinger -u https://www.example.com --tls-mode gm

# Standard TLS only, without GM/TLS fallback
hfinger -u https://www.example.com --tls-mode std
```

Query passive mode JSONL results:

```bash
hfinger passive query passive.jsonl
hfinger passive query passive.jsonl --cms Cloudflare --min-confidence 80
```

## Toolchain Integration

HFinger can be used as the fingerprinting layer in a broader reconnaissance and validation workflow.

```bash
# httpx or another liveness tool -> HFinger batch fingerprinting
httpx -l domains.txt -silent > alive.txt
hfinger -f alive.txt -j hfinger.json

# Chain HFinger with Burp Suite / mitmproxy / Clash through an upstream proxy
hfinger -l 127.0.0.1:8888 -p http://127.0.0.1:8080 --passive-store passive.jsonl

# Feed JSON output to scripts, asset platforms, or validation pipelines
hfinger -f alive.txt -j hfinger.json
```

Typical integrations:

- Liveness tools discover reachable targets, then HFinger identifies server-side stacks
- Browser, Burp Suite, or mobile debugging traffic flows through HFinger for passive fingerprinting
- Scripts consume JSON/JSONL output and branch on `cms`, `category`, `confidence`, and `evidence`
- nuclei, xray, or other validators can use HFinger results to select more precise templates or plugins

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

`rules test` replays positive and negative examples declared in rules. It is useful for reducing false positives and false negatives before submitting community rules.

Rule authoring documentation:

- [中文规则 Wiki](docs/RULES_WIKI.md)
- [English Rules Wiki](docs/RULES_WIKI_EN.md)

The rules wiki includes prompts for AI-assisted rule drafting. AI output should be treated as a draft and must be manually reviewed and validated with `rules lint/test`.

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
    --passive-store string Write passive mode results to a JSONL file
    --client-cert string   Mutual TLS client certificate
    --client-key string    Mutual TLS client private key
    --gm-client-cert string Mutual GM/TLS client certificate
    --gm-client-key string  Mutual GM/TLS client private key
    --tls-mode string      Active request TLS mode: auto, gm, std
-j, --output-json string   Write JSON output
-x, --output-xml string    Write XML output
-s, --output-xlsx string   Write XLSX output
-c, --check-update         Check tool updates
    --update               Show rule update guidance
    --upgrade              Upgrade the tool
-v, --version              Show version
```

Passive result query:

```text
hfinger passive query [jsonl-file]
    --url string             Filter by URL substring
    --cms string             Filter by product name
    --category string        Filter by category
    --min-confidence int     Filter by minimum confidence
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

# HFinger

#### [简体中文](README.md) | English

![logo](images/logo.png)

HFinger is a server-side fingerprinting tool for security testing. It helps identify websites, web services, CMS products, backend frameworks, middleware, API gateways, WAF/CDN providers, load balancers, and common server-side components.

HFinger ships with built-in core fingerprint rules and works out of the box. It also supports external YAML rules for community contributions, private products, and internal enterprise systems.

The current build includes **1756** built-in fingerprint rules covering **1488** server-side products, web frameworks, CMS products, middleware, CDN/WAF providers, honeypots, and related components.

## Positioning

HFinger is not intended to replace vulnerability scanners. It is designed to be the server-side technology identification layer in a security testing workflow. It answers "what server-side components are behind this target" and returns evidence plus confidence so results can be reviewed, automated, and reused by downstream tools.

Compared with simple keyword-based fingerprinting, HFinger focuses on:

- Built-in core rules without shipping extra rule files
- External YAML rules for community and private rule maintenance
- Multi-source evidence across headers, cookies, HTML, JavaScript, favicon, JSON/API, TLS, HTTP behavior, and Server banners
- Evidence and confidence output for review and automation
- Both active scanning and passive proxy fingerprinting

## Differentiators

HFinger is designed to make server-side fingerprinting governable, reviewable, and easy to integrate:

- Unified rule sources: all built-in rules live under `rulesets/core/*.yaml` and are embedded into release binaries; external rules use the same YAML semantic model.
- Evidence-backed results: output includes product name, category, version, confidence, and evidence instead of only a product label.
- Active and passive coverage: HFinger supports both batch active scanning and passive HTTP/HTTPS proxy fingerprinting.
- GM/TLCP support: active mode supports standard TLS and TLCP with auto/gm/std modes; passive MITM can adaptively route standard TLS and TLCP handshakes on the same listener.
- Rule quality governance: `rules lint/test/stats` and positive/negative fixtures help reduce false positives and false negatives over time.
- Toolchain integration: httpx JSONL input plus JSON/JSONL/XLSX output and an LLM manifest make it easy to connect HFinger with ASM, Burp Suite, mitmproxy, nuclei, SIEM, and external agent/Skill workflows.

## Features

- Server-side technology fingerprinting
- Active scanning and passive MITM mode
- Built-in core rules that work out of the box
- External YAML rule loading
- Header, body, title, cookie, status, redirect, and favicon matching
- HTML meta, DOM selectors, script source, JavaScript/CSS hash, favicon mmh3/MD5/SHA1/SHA256, DNS CNAME/NS/TXT/IP, JSON/API, TLS certificate/ALPN/version/cipher, HTTP behavior, and Server banner matching
- Active probes for common paths, API endpoints, error pages, 404 pages, HEAD, OPTIONS, Alt-Svc, and cache-chain behavior
- WAF/CDN, framework, CMS, middleware, version extraction, and honeypot identification
- Evidence and confidence in scan results
- JSON, JSONL, XML, and XLSX output
- Passive mode JSONL persistence and query
- HTTP/1.1 and HTTP/2 support
- Active requests with standard TLS, TLCP fallback, and client-certificate authentication
- Passive MITM with adaptive standard TLS / TLCP handshakes
- Proxy, random User-Agent, and multithreading support
- Rule validation commands for custom rule maintenance
- Machine-readable LLM/agent capability manifest for external Skill orchestration

## Capability Coverage

| Capability | Current support |
| --- | --- |
| HTTP Header fingerprints | `header.contains`, `header.regex` |
| Cookie fingerprints | `cookie.contains` |
| HTML body fingerprints | `body.contains`, `body.regex` |
| HTML tags / Meta / DOM | `html.meta.contains`, `html.selector.exists`, `script.src.contains`, Body/Regex |
| JavaScript reference paths | `script.src.contains`, `body.contains` |
| JavaScript Hash | `script.hash.md5`, `script.hash.sha1`, `script.hash.sha256` |
| Stylesheet / CSS Hash | `stylesheet.hash.md5`, `stylesheet.hash.sha1`, `stylesheet.hash.sha256` |
| Favicon fingerprints | `favicon.hash`, `favicon.hash.md5`, `favicon.hash.sha1`, `favicon.hash.sha256` |
| Static resource paths | Active probes, `path.exists`, `script.src.contains`, Body/Regex |
| 404 / error page fingerprints | Default error-page probe and rule-level probes |
| TLS/HTTPS fingerprints | Certificate Subject/Issuer/DNSNames, ALPN, TLS version, cipher, JA3S-style summary |
| DNS / CDN resolution chain | DNS CNAME, NS, TXT, and IP evidence for CDN/WAF/hosting identification |
| HTTP protocol behavior | HTTP version, HEAD/OPTIONS Allow, Alt-Svc/HTTP/3 hints, compression, ETag, Accept-Ranges, cache headers, status code, redirect |
| Active probes / API fingerprints | Rule `probes.request` supports method/path/header/body |
| WAF/CDN / framework / CMS / middleware | Built-in category rules, DNS CNAME/NS/TXT/IP, Header/Cookie/Body/TLS, and behavior probes |
| Version fingerprints | Regex version extraction with `extract` |
| Combined identification | score/any/all, negative matchers, confidence, evidence |
| Honeypot identification | Explicit honeypot rules plus conflict, abnormal-response, and response-similarity heuristics |

## Project Structure

```text
.
├── cmd/                 CLI flags and subcommands
├── config/              Global configuration and result structures
├── docs/                User documentation and rules wiki
├── icon_hash/           Favicon hash helper
├── logger/              Logging
├── models/              Active scanning and passive proxy fingerprinting
├── output/              JSON, JSONL, XML, and XLSX output
├── rules/               Built-in rules, YAML loading, validation, and matching engine
├── rulesets/            Built-in YAML rule sources embedded into release binaries
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

`-f` also supports common JSONL liveness output such as `httpx -json`. HFinger reads `url` first, then falls back to `input` / `host` plus `scheme`:

```bash
httpx -l domains.txt -json -silent > alive.jsonl
hfinger -f alive.jsonl -j fingerprint-results.json
hfinger -f alive.jsonl --output-jsonl fingerprint-results.jsonl
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

Results include product name, category, version, status code, Server header, title, confidence, and evidence.

### Passive Mode

Start a local proxy:

```bash
hfinger -l 127.0.0.1:8888 -s result.xlsx --passive-store passive.jsonl
```

Configure your browser or another tool to use `127.0.0.1:8888` as the proxy. HFinger forwards traffic and fingerprints server responses at the same time.
For long-running passive mode, enable JSONL rotation to prevent one result file from growing indefinitely:

```bash
hfinger -l 127.0.0.1:8888 --passive-store passive.jsonl --passive-store-max-bytes 104857600
```

Use an upstream proxy:

```bash
hfinger -l 127.0.0.1:8888 -p http://127.0.0.1:7777 -s result.xlsx --passive-store passive.jsonl
```

For HTTPS passive fingerprinting, import the generated certificates under the `certs` directory into your browser or system trust store. Standard TLS clients should trust `ca.crt`, while TLCP clients should trust `gm_ca.crt`.

Note: passive mode uses an adaptive TLS/TLCP handshake. Standard TLS clients and TLCP clients are handled on the same listener and automatically select the matching handshake flow.

### Mutual TLS / TLCP

If a target requires a client certificate, provide the certificate and private key:

```bash
hfinger -u https://www.example.com --client-cert client.crt --client-key client.key
```

For TLCP single-certificate mutual authentication, provide a GM client certificate explicitly:

```bash
hfinger -u https://www.example.com --gm-client-cert gm-client.crt --gm-client-key gm-client.key
```

For TLCP dual-certificate mutual authentication, provide the signing and encryption client certificates explicitly:

```bash
hfinger -u https://www.example.com \
  --gm-client-sign-cert gm-sign.crt --gm-client-sign-key gm-sign.key \
  --gm-client-enc-cert gm-enc.crt --gm-client-enc-key gm-enc.key
```

When only `--client-cert/--client-key` is provided, HFinger uses it for standard TLS and also attempts to load it as a TLCP single-certificate client certificate. If the GM client certificate is different, use `--gm-client-cert/--gm-client-key` or the explicit TLCP dual-certificate flags.

### Active TLS Mode

Active requests use `auto` mode by default, so users do not need to specify an extra option. `auto` tries standard TLS first. If standard TLS fails with a GM transport-like error, HFinger automatically tries TLCP fallback.

The built-in GM transport support now selects GoTLCP as the only provider. It supports TLCP suites: `ECC_SM4_GCM_SM3(0xe053)`, `ECC_SM4_CBC_SM3(0xe013)`, `ECDHE_SM4_GCM_SM3(0xe051)`, and `ECDHE_SM4_CBC_SM3(0xe011)`. If a target requires another unsupported protocol variant or cipher suite, HFinger reports the supported range in the connection error.

If the target type is already known, force the mode explicitly:

```bash
# Show built-in TLS / GM capabilities
hfinger tls capabilities

# TLCP only
hfinger -u https://www.example.com --tls-mode gm

# Standard TLS only, without TLCP fallback
hfinger -u https://www.example.com --tls-mode std
```

Query passive mode JSONL results:

```bash
hfinger passive query passive.jsonl
hfinger passive query passive.jsonl --cms Cloudflare --min-confidence 80 --limit 100
```

## Toolchain Integration

HFinger can be used as the fingerprinting layer in a broader reconnaissance and validation workflow. Liveness discovery, path discovery, and vulnerability validation should stay in their own tools, while HFinger turns targets into evidence-backed server-side technology results.

### httpx / Internal Liveness Tools -> HFinger

```bash
# 1. Discover reachable URLs with httpx
httpx -l domains.txt -silent > alive.txt

# 2. Run evidence-backed fingerprinting with HFinger
hfinger -f alive.txt -j fingerprint-results.json
```

If an internal ASM or asset platform already exports reachable URLs, use one URL per line:

```bash
hfinger -f asm-alive-urls.txt -j fingerprint-results.json -s hfinger.xlsx
```

### katana / ffuf -> HFinger Multi-Path Fingerprinting

When the homepage does not expose enough evidence, discover more paths first and then feed them to HFinger:

```bash
# Discover paths with katana
katana -list alive.txt -silent -d 2 > discovered-urls.txt

# ffuf or another content discovery tool can also produce URL lists
ffuf -w paths.txt -u https://www.example.com/FUZZ -mc all -of csv -o ffuf.csv

# Fingerprint discovered URLs
hfinger -f discovered-urls.txt -j hfinger-paths.json
```

### Burp Suite / mitmproxy -> Passive HFinger

HFinger can sit in the proxy chain with a browser, Burp Suite, or mitmproxy and passively collect server-side fingerprints.

```bash
# HFinger listens locally and forwards traffic to Burp Suite
hfinger -l 127.0.0.1:8888 -p http://127.0.0.1:8080 --passive-store passive.jsonl

# Configure the browser proxy as 127.0.0.1:8888
# Configure Burp Suite to listen on 127.0.0.1:8080
```

Query passive results:

```bash
hfinger passive query passive.jsonl
hfinger passive query passive.jsonl --category api-gateway --min-confidence 80
hfinger passive query passive.jsonl --cms Nacos
```

### HFinger -> Precise nuclei Validation

HFinger does not replace vulnerability scanners. A better workflow is to identify components first, then select nuclei templates based on the detected products.

```bash
# Fingerprint assets
hfinger -f alive.txt -j fingerprint-results.json

# Example: extract Nacos targets and run Nacos-related nuclei templates
jq -r '.[] | select(.cms | test("Nacos"; "i")) | .url' fingerprint-results.json > nacos-targets.txt
nuclei -l nacos-targets.txt -tags nacos -o nuclei-nacos.txt

# Example: extract Swagger / OpenAPI targets
jq -r '.[] | select(.cms | test("Swagger|OpenAPI"; "i")) | .url' fingerprint-results.json > api-docs-targets.txt
nuclei -l api-docs-targets.txt -tags exposure,swagger,openapi -o nuclei-api-docs.txt
```

### nmap / Protocol Scanning -> HFinger Web Context

nmap is useful for ports and protocol banners. HFinger is useful for HTTP/HTTPS server-side components. Use nmap to find Web ports, then convert them to URLs:

```bash
nmap -p 80,443,8080,8443,9000,9090 -oX nmap.xml 192.168.1.0/24

# Convert nmap results to URL lists, then fingerprint them
hfinger -f web-urls-from-nmap.txt -j hfinger-nmap.json
```

### JSON / JSONL -> ASM, SIEM, and Custom Scripts

HFinger JSON output is suitable for asset platforms, SIEM pipelines, and custom orchestration scripts. Downstream tools should primarily consume:

- `url`: target URL
- `cms`: matched product or component
- `category`: component category
- `confidence`: confidence score
- `evidence`: matched evidence
- `server` / `title` / `statuscode`: supporting context

Examples:

```bash
# High-confidence component inventory
jq -r '.[] | select(.confidence >= 80) | [.url, .cms, .category, .confidence] | @tsv' fingerprint-results.json

# Split tasks by component type
jq -r '.[] | select(.category == "waf" or .category == "cdn") | .url' fingerprint-results.json > edge-assets.txt
jq -r '.[] | select(.category == "middleware") | .url' fingerprint-results.json > middleware-assets.txt
```

## Rule Management

HFinger uses built-in core rules. User and community rules are written in YAML.

### Rule Governance and Built-in Rule Sources

All built-in rule sources live under `rulesets/core/*.yaml` and are embedded into release binaries.

Built-in rules are split by source tier and component category:

- `curated-*.yaml`: continuously curated high-value server-side rules.
- `migrated-*.yaml`: existing rules standardized into the unified YAML schema and split by component category.

This split only affects maintenance. At runtime, HFinger loads all built-in YAML files and compiles them into in-memory matching structures.

Governance principles:

- Built-in rules use the unified YAML semantic model: `id/name/category/vendor/tags/match/negative/metadata/examples`
- New core rules must include clear evidence text, category, references, and positive/negative examples
- Community contributions should use YAML; maintainers decide whether reviewed rules are promoted into built-in releases
- Rule quality should be measured by `rules lint` and `rules test`, not by rule count alone
- The rule schema is available at `schemas/rule.schema.json` and can be associated with YAML files in IDEs for field and matcher validation

Recommended rule categories:

```text
cms, oa, middleware, api-gateway, devops, cloud-native,
observability, storage, database, security-device, cdn, waf,
framework, ai-service, iot-device
```

Show runtime rule distribution:

```bash
hfinger rules stats
```

The output includes total rule count, product count, lint error/warning counts, `tier.curated` / `tier.migrated` tier counts, lint distribution by tier, and category distribution.

Show rule remediation priorities:

```bash
hfinger rules doctor
hfinger rules doctor --max-rules 0
```

`rules doctor` aggregates lint findings, prints the most common issue types, and lists rules that should be cleaned up first with suggested remediation directions. `--max-rules 0` prints summary output only and is suitable for CI baseline checks.

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
    "version": "1.2.3",
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
-f, --file string          Read targets from a URL list or httpx JSONL file
-l, --listen string        Start passive proxy listener
-p, --proxy string         Use upstream proxy
-t, --thread int           Number of threads
-r, --redirect int         Max redirects
    --rules stringArray    Load external YAML rule file or directory
    --passive-store string Write passive mode results to a JSONL file
    --passive-store-max-bytes int
                           Rotate passive JSONL store after it exceeds this size in bytes; 0 disables rotation
    --client-cert string   Mutual TLS client certificate
    --client-key string    Mutual TLS client private key
    --gm-client-cert string TLCP single-certificate client certificate
    --gm-client-key string  TLCP single-certificate client private key
    --gm-client-sign-cert string TLCP dual-certificate signing client certificate
    --gm-client-sign-key string  TLCP dual-certificate signing client private key
    --gm-client-enc-cert string TLCP dual-certificate encryption client certificate
    --gm-client-enc-key string  TLCP dual-certificate encryption client private key
    --tls-mode string      Active request TLS mode: auto, gm, std
-j, --output-json string   Write JSON output
    --output-jsonl string  Write JSONL output for LLM/agent/script pipelines
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
    --limit int              Limit returned records
```

### LLM / Agent / Skill Integration

HFinger does not put LLMs into the final fingerprint decision path. LLMs and agents should call HFinger as a deterministic tool: HFinger scans, matches, and returns evidence plus confidence, while LLM/Skill workflows consume structured results to handle orchestration, triage, and explanation tasks that plain CLI flags cannot fully cover.

Print the machine-readable capability manifest:

```text
hfinger llm manifest
```

Print external agent Skill templates:

```text
hfinger llm skills
```

Run batch scanning with JSONL output for streaming LLM/agent consumption:

```bash
hfinger -f alive.jsonl --output-jsonl hfinger-results.jsonl
```

The integration chain is:

```text
user intent
  -> LLM/Agent parses scope and objectives
  -> Agent runs hfinger or reads existing JSONL
  -> HFinger emits deterministic evidence/confidence
  -> Agent applies Skill/playbook logic for triage, clustering, tool orchestration, or rule drafting
```

HFinger does not call an LLM by itself. In daily penetration testing, this is useful when your environment can execute commands and read files, such as Trae, Claude Code, Cursor Agent, a custom agent, Dify, Coze, LangChain, or AutoGen. A normal chat UI that cannot run commands is only useful for explaining JSONL snippets you provide.

A directly usable penetration-testing orchestration flow:

```bash
# 1. Run httpx liveness probing and write JSONL
httpx -l domains.txt -json -silent > alive.jsonl

# 2. Run HFinger and write evidence-backed JSONL
hfinger -f alive.jsonl --output-jsonl hfinger-results.jsonl

# 3. Extract high-confidence API gateways and validate with nuclei
jq -r 'select(.category=="api-gateway" and .confidence>=80) | .url' hfinger-results.jsonl > api-gateway.txt
nuclei -l api-gateway.txt -tags exposure,api,gateway -o nuclei-api-gateway.txt

# 4. Extract admin/DevOps targets for katana or ffuf follow-up
jq -r 'select((.category=="devops" or .category=="middleware") and .confidence>=80) | .url' hfinger-results.jsonl > high-value.txt
katana -list high-value.txt -silent -o katana-high-value.txt

# 5. Extract confirmed web targets for optional nmap-side validation
jq -r 'select(.confidence>=80) | .url' hfinger-results.jsonl > confirmed-web.txt
```

When the authorized scope includes non-HTTP ports, use lightweight service fingerprinting:

```bash
hfinger service scan 10.0.0.5 --ports 22,3306,5432,6379,3389,1883 --output-jsonl services.jsonl
```

For large result sets, cluster likely same-origin systems:

```bash
hfinger cluster jsonl hfinger-results.jsonl --min-size 2
```

For AI penetration-testing systems, load these at startup:

```bash
hfinger llm manifest
hfinger llm skills
```

`manifest` exposes tool capabilities, inputs, outputs, result fields, and schema paths. `skills` exposes playbooks for asset triage, toolchain orchestration, rule authoring, honeypot review, non-HTTP service identification, and cross-asset clustering. Schemas are available at:

- `schemas/result.schema.json`
- `schemas/llm-skill.schema.json`
- `schemas/rule.schema.json`



LLM/Skill workflows are useful for dynamic decisions that should not be hard-coded into HFinger flags:

- Translate operator intent into filters, such as "find high-confidence API gateways and Spring Boot admin surfaces, then generate nuclei/katana commands".
- Split large result sets by business priority, tool type, confidence, evidence strength, and authorized scope.
- Generate follow-up command plans from fingerprints without replacing HFinger's deterministic matching.
- Draft YAML rules from HTTP/TLS/DNS/favicon evidence, then validate them with `rules lint/test/doctor`.
- When honeypot, conflicting-fingerprint, or universal-response signals appear, generate low-impact confirmation steps instead of increasing active probing.
- For authorized non-HTTP ports, run `hfinger service scan` to identify SSH, Redis, MySQL, PostgreSQL, RDP, MQTT, and generic TCP banners.
- For large JSONL outputs, run `hfinger cluster jsonl` to group likely same-origin systems by favicon, TLS, DNS, title, server, and resource hashes.

A more useful agent instruction:

```text
Build a follow-up test plan from hfinger-results.jsonl:
- Only process targets with confidence >= 80.
- Write API gateways to api-gateway.txt and produce nuclei commands.
- Write DevOps, admin, and middleware targets to high-value.txt and produce katana commands.
- Mark WAF/CDN targets with rate-limit guidance.
- For honeypot or conflicting fingerprints, output only low-impact confirmation steps.
- Do not re-identify fingerprints or invent products not present in HFinger output.
```

`hfinger llm skills` prints machine-readable playbooks for external agents. These are not decorative docs for humans. Each playbook includes:

- `name`: capability name, such as result triage, toolchain orchestration, rule authoring, or honeypot review.
- `purpose`: the concrete problem solved by the playbook.
- `inputs` / `outputs`: what the agent should read and produce.
- `required_tools`: external tools required by the workflow.
- `risk_level` / `do_not_do`: risk boundaries and prohibited actions.
- `example_user_prompt`: natural-language examples that should trigger the playbook.
- `when_to_use`: when to trigger the playbook.
- `decision_rules`: how to decide based on confidence, evidence, category, and honeypot risk.
- `workflow`: executable or adaptable command steps.

Typical LLM/Skill scenarios:

- Asset triage: read `hfinger-results.jsonl`, group findings by `category`, `cms`, `version`, `confidence`, and `evidence`, then produce prioritized targets.
- Toolchain orchestration: turn high-confidence API gateway, DevOps, admin surface, security device, or middleware findings into nuclei, ffuf, katana, or nmap inputs.
- Rule authoring: generate YAML rule drafts from HTTP headers, cookies, body snippets, favicon, DNS CNAME, TLS certificates, and JavaScript/CSS hashes, then validate them with `rules lint/test/doctor`.
- Rule review: check whether a rule depends on generic keywords or lacks strong evidence, negative matchers, and positive/negative examples.
- Honeypot review: when results include `category: honeypot`, `Potential Honeypot`, conflicting technologies, or similar responses across many paths, reduce intrusive probing and generate low-impact confirmation steps.
- Non-HTTP service identification: within an explicitly authorized port scope, identify SSH, Redis, MySQL, PostgreSQL, RDP, MQTT, and generic TCP services.
- Cross-asset clustering: group assets that share favicon, TLS certificates, DNS edge networks, titles, server headers, or static resource hashes.
- Report explanation: convert evidence and confidence into auditable security-report text.

Skills are external agent workflows, not runtime directories required by the HFinger repository. Users can define Skills in their own agent environment and have them call `hfinger llm manifest`, `hfinger llm skills`, `hfinger --output-jsonl`, and `hfinger rules lint/test/doctor` for more complex penetration-testing workflows.

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

See [Apache License 2.0](LICENSE).

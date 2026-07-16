# HFinger Rules Wiki

This document explains how to write external YAML fingerprint rules for HFinger.

HFinger ships with built-in core rules. User and community rules should be written in YAML and loaded with `--rules`.

## 1. Quick Start

Create a rule file:

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
          evidence: Page title matched
        - type: header.contains
          key: Set-Cookie
          value: example_session
          weight: 40
          evidence: Cookie fingerprint matched

metadata:
  references:
    - https://example.com
```

Validate the rule:

```bash
hfinger rules lint ./example-admin.yaml
```

Use the rule:

```bash
hfinger -u https://www.example.com --rules ./example-admin.yaml
```

## 2. Rule Structure

A rule describes one server-side product or component.

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
    reason: Avoid false positives

metadata:
  references:
    - https://example.com
  confidence: high
  updated_at: 2026-07-15
```

## 3. Top-Level Fields

| Field | Required | Description |
|-|-|-|
| `id` | Yes | Unique rule ID. Use lowercase letters, numbers, and hyphens. |
| `name` | Yes | Product or component name |
| `category` | Yes | Category such as `web`, `cms`, `middleware`, `waf`, `cdn`, `gateway` |
| `vendor` | No | Vendor name |
| `priority` | No | Priority for future conflict resolution |
| `tags` | No | Tags |
| `match` | Yes | Positive match rules |
| `negative` | No | Negative rules to reduce false positives |
| `metadata` | No | References and maintenance metadata |

## 4. Match Strategy

`match.strategy` supports:

| Strategy | Description |
|-|-|
| `score` | Accumulates matcher weights and matches when the score reaches `threshold` |
| `any` | Matches when any matcher matches |
| `all` | Matches only when all matchers match |

Prefer `score` for multi-evidence fingerprinting.

Example:

```yaml
match:
  strategy: score
  threshold: 70
```

## 5. Probe

A probe describes one HTTP request.

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

Active mode automatically requests `request.path` values declared by rules.

## 6. Matcher

A matcher is one concrete match condition.

Common fields:

| Field | Required | Description |
|-|-|-|
| `type` | Yes | Matcher type |
| `key` | No | Header or cookie field name |
| `value` | No | One match value |
| `values` | No | Multiple match values |
| `weight` | No | Score weight. Default is 100 |
| `evidence` | No | Evidence message |
| `case_sensitive` | No | Whether matching is case-sensitive. Default is true |

## 7. Supported Matcher Types

| Type | Description |
|-|-|
| `body.contains` | Response body contains a string |
| `body.regex` | Response body matches a regex |
| `header.contains` | Header name or value contains a string |
| `header.regex` | Header matches a regex |
| `title.contains` | Page title contains a string |
| `cookie.contains` | `Set-Cookie` contains a string |
| `status.eq` | Status code equals a value |
| `status.in` | Status code is in a list |
| `favicon.hash` | Favicon mmh3 hash matches |
| `path.exists` | Probed path returns 2xx/3xx |
| `redirect.to` | `Location` header contains a value |
| `script.src.contains` | Script src contains a value |
| `html.meta.contains` | Meta tag contains a value |

## 8. Negative Rules

`negative` reduces false positives. If any negative matcher matches, the rule is excluded.

```yaml
negative:
  - type: header.contains
    key: Server
    value: openresty
    reason: Avoid confusing OpenResty with Nginx
```

## 9. Authoring Suggestions

Recommended priority:

1. Prefer strong evidence such as unique headers, cookies, fixed asset paths, and API error shapes
2. Then use stable HTML, JS/CSS paths, default APIs, and default error pages
3. Use titles, common keywords, and favicon hashes carefully
4. Add `negative` matchers for rules prone to false positives
5. Provide `metadata.references` whenever possible

## 10. Rule Quality Check

```bash
hfinger rules lint ./rules/
hfinger rules test ./rules/
```

Currently, `rules test` runs lightweight rule validation. Fixture-based positive and negative replay can be added later.

## 11. FAQ

### Can I still use the old finger.json?

No. Core rules are built into the binary. External rules use YAML.

### Can external rules override built-in rules?

Yes. An external rule with the same `id` overrides the built-in rule. A different `id` adds a new rule.

### Can one file contain multiple rules?

Yes. Single-rule YAML and multi-rule YAML are both supported:

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

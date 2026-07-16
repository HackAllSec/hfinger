package rulesets

import "embed"

// CoreFS contains curated YAML rules that are embedded into release binaries.
//
//go:embed core/*.yaml
var CoreFS embed.FS

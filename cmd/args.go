package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"hfinger/config"
	"hfinger/logger"
	"hfinger/models"
	"hfinger/output"
	"hfinger/passive"
	"hfinger/releasecheck"
	"hfinger/rules"
	"hfinger/utils"
)

var RootCmd = &cobra.Command{
	Use:   "hfinger",
	Short: "A high-performance command-line tool for web framework, CDN and CMS fingerprinting",
	Run: func(cmd *cobra.Command, args []string) {
		url, _ := cmd.Flags().GetString("url")
		file, _ := cmd.Flags().GetString("file")
		listen, _ := cmd.Flags().GetString("listen")

		if url != "" {
			models.ProcessURL(url)
		}

		if file != "" {
			models.ProcessFile(file)
		}

		if listen != "" {
			models.MitmServer(listen)
		}
	},
	PreRun: func(cmd *cobra.Command, args []string) {
		url, _ := cmd.Flags().GetString("url")
		file, _ := cmd.Flags().GetString("file")
		listen, _ := cmd.Flags().GetString("listen")
		proxy, _ := cmd.Flags().GetString("proxy")
		clientCert, _ := cmd.Flags().GetString("client-cert")
		clientKey, _ := cmd.Flags().GetString("client-key")
		gmClientCert, _ := cmd.Flags().GetString("gm-client-cert")
		gmClientKey, _ := cmd.Flags().GetString("gm-client-key")
		gmClientSignCert, _ := cmd.Flags().GetString("gm-client-sign-cert")
		gmClientSignKey, _ := cmd.Flags().GetString("gm-client-sign-key")
		gmClientEncCert, _ := cmd.Flags().GetString("gm-client-enc-cert")
		gmClientEncKey, _ := cmd.Flags().GetString("gm-client-enc-key")
		tlsMode, _ := cmd.Flags().GetString("tls-mode")
		thread, _ := cmd.Flags().GetInt("thread")
		redirect, _ := cmd.Flags().GetInt("redirect")
		outputJSON, _ := cmd.Flags().GetString("output-json")
		outputXML, _ := cmd.Flags().GetString("output-xml")
		outputXLSX, _ := cmd.Flags().GetString("output-xlsx")
		rulePaths, _ := cmd.Flags().GetStringArray("rules")
		passiveStore, _ := cmd.Flags().GetString("passive-store")
		passiveStoreMaxBytes, _ := cmd.Flags().GetInt64("passive-store-max-bytes")
		versionFlag, _ := cmd.Flags().GetBool("version")
		checkFlag, _ := cmd.Flags().GetBool("check-update")
		updateFlag, _ := cmd.Flags().GetBool("update")
		upgradeFlag, _ := cmd.Flags().GetBool("upgrade")

		if versionFlag {
			color.Green("hfinger version: %s", config.Version)
			os.Exit(0)
		}

		if redirect < 1 {
			logger.Error("Error: The number of redirect cannot be less than 1.")
			os.Exit(1)
		}

		utils.ConfigureClientCertificates(clientCert, clientKey, gmClientCert, gmClientKey, gmClientSignCert, gmClientSignKey, gmClientEncCert, gmClientEncKey)
		if err := utils.ConfigureTLSMode(tlsMode); err != nil {
			logger.Error("Error: %v", err)
			os.Exit(1)
		}
		err := utils.InitializeHTTPClient(proxy, 30*time.Second, redirect)
		if err != nil {
			logger.Error("Error: %v", err)
			os.Exit(1)
		}

		if checkFlag {
			utils.CheckForUpdates()
			os.Exit(0)
		}

		if updateFlag {
			utils.Update()
			os.Exit(0)
		}

		if upgradeFlag {
			utils.Upgrade()
			os.Exit(0)
		}

		inputCount := countNonEmpty(url, file, listen)
		if inputCount == 0 {
			cmd.Help()
			logger.Error("Error: Must specify one of the -u, -f, or -l parameters!")
			os.Exit(1)
		}
		if inputCount > 1 {
			logger.Error("Error: You can only choose one of the -u, -f or -l parameters!")
			os.Exit(1)
		}
		if url != "" {
			_, urlErr := utils.GetBaseURL(url)
			if urlErr != nil {
				logger.Error("Error: %v", urlErr)
				os.Exit(1)
			}
		}

		if thread < 1 {
			logger.Error("Error: The number of threads cannot be less than 1.")
			os.Exit(1)
		}
		if countNonEmpty(outputJSON, outputXML, outputXLSX) > 1 {
			logger.Error("Error: You can only choose one output format at a time.")
			os.Exit(1)
		}
		if outputJSON != "" {
			err = output.SetOutput("json", outputJSON)
		}
		if outputXML != "" {
			err = output.SetOutput("xml", outputXML)
		}
		if outputXLSX != "" {
			err = output.SetOutput("xlsx", outputXLSX)
		}
		if err != nil {
			logger.Error("Error: %v", err)
			os.Exit(1)
		}

		if err := rules.Init(rulePaths); err != nil {
			logger.Error("Error: Failed to load fingerprint rules: %v", err)
			os.Exit(1)
		}
		passive.SetStorePath(passiveStore)
		passive.SetStoreMaxBytes(passiveStoreMaxBytes)
		models.ShowFingerPrints()
		models.SetThread(thread)
		models.SetMaxRedirects(redirect)
	},
}

func countNonEmpty(values ...string) int {
	count := 0
	for _, value := range values {
		if value != "" {
			count++
		}
	}
	return count
}

func init() {
	PrintBanner()
	RootCmd.Flags().StringP("url", "u", "", "Specify the recognized target,example: https://www.example.com")
	RootCmd.Flags().StringP("file", "f", "", "Read assets from local files for fingerprint recognition, with one target per line")
	RootCmd.Flags().StringP("listen", "l", "", "Using a proxy resource collector to retrieve targets, example: 127.0.0.1:6789")
	RootCmd.Flags().StringP("output-json", "j", "", "Output all results to a JSON file")
	RootCmd.Flags().StringP("output-xml", "x", "", "Output all results to a XML file")
	RootCmd.Flags().StringP("output-xlsx", "s", "", "Output all results to a Excel file")
	RootCmd.Flags().StringP("proxy", "p", "", "Specify the proxy for accessing the target, supporting HTTP and SOCKS, example: http://127.0.0.1:8080")
	RootCmd.Flags().String("client-cert", "", "TLS client certificate for mutual TLS targets")
	RootCmd.Flags().String("client-key", "", "TLS client private key for mutual TLS targets")
	RootCmd.Flags().String("gm-client-cert", "", "TLCP client certificate for single-certificate mutual authentication")
	RootCmd.Flags().String("gm-client-key", "", "TLCP client private key for single-certificate mutual authentication")
	RootCmd.Flags().String("gm-client-sign-cert", "", "TLCP signing client certificate for dual-certificate mutual authentication")
	RootCmd.Flags().String("gm-client-sign-key", "", "TLCP signing client private key for dual-certificate mutual authentication")
	RootCmd.Flags().String("gm-client-enc-cert", "", "TLCP encryption client certificate for dual-certificate mutual authentication")
	RootCmd.Flags().String("gm-client-enc-key", "", "TLCP encryption client private key for dual-certificate mutual authentication")
	RootCmd.Flags().String("tls-mode", "auto", "TLS mode for active requests: auto, gm, or std")
	RootCmd.Flags().StringArray("rules", nil, "Load external YAML rule file or directory; can be specified multiple times")
	RootCmd.Flags().String("passive-store", "", "Write passive mode fingerprint results to a JSONL file")
	RootCmd.Flags().Int64("passive-store-max-bytes", 0, "Rotate passive JSONL store when it exceeds this size in bytes; 0 disables rotation")
	RootCmd.Flags().IntP("thread", "t", 100, "Number of fingerprint recognition threads")
	RootCmd.Flags().IntP("redirect", "r", 5, "Number of max redirects")
	RootCmd.Flags().BoolP("check-update", "c", false, "Check for updates and upgrades")
	RootCmd.Flags().BoolP("update", "", false, "Show rule update guidance")
	RootCmd.Flags().BoolP("upgrade", "", false, "Upgrade to the latest version")
	RootCmd.Flags().BoolP("version", "v", false, "Display the current version of the tool")

	RootCmd.AddCommand(rulesCmd)
	RootCmd.AddCommand(passiveCmd)
	RootCmd.AddCommand(tlsCmd)
	RootCmd.AddCommand(devCmd)
}

var rulesCmd = &cobra.Command{
	Use:   "rules",
	Short: "Manage external YAML fingerprint rules",
}

var passiveCmd = &cobra.Command{
	Use:   "passive",
	Short: "Query passive mode JSONL results",
}

var tlsCmd = &cobra.Command{
	Use:   "tls",
	Short: "Inspect TLS and TLCP capabilities",
}

var devCmd = &cobra.Command{
	Use:   "dev",
	Short: "Developer maintenance commands",
}

var tlsCapabilitiesCmd = &cobra.Command{
	Use:   "capabilities",
	Short: "Show built-in TLS and TLCP providers",
	Run: func(cmd *cobra.Command, args []string) {
		for _, capability := range utils.TLSCapabilities() {
			fmt.Println(capability)
		}
	},
}

var devReleaseCheckCmd = &cobra.Command{
	Use:   "release-check",
	Short: "Check release version metadata and rule schema presence",
	Run: func(cmd *cobra.Command, args []string) {
		report, err := releasecheck.Check()
		if err != nil {
			logger.Error("Error: %v", err)
			os.Exit(1)
		}
		fmt.Printf("version=%s\n", report.Version)
		fmt.Printf("changelog.version=%s\n", report.ChangelogVersion)
		fmt.Printf("winres.version=%s\n", report.WinresVersion)
		fmt.Printf("schema=%s\n", report.SchemaPath)
	},
}

var passiveQueryCmd = &cobra.Command{
	Use:   "query [jsonl-file]",
	Short: "Query passive mode JSONL results",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		urlFilter, _ := cmd.Flags().GetString("url")
		cmsFilter, _ := cmd.Flags().GetString("cms")
		categoryFilter, _ := cmd.Flags().GetString("category")
		minConfidence, _ := cmd.Flags().GetInt("min-confidence")
		limit, _ := cmd.Flags().GetInt("limit")
		filter := passive.QueryFilter{
			URL:           urlFilter,
			CMS:           cmsFilter,
			Category:      categoryFilter,
			MinConfidence: minConfidence,
			Limit:         limit,
		}
		if err := printPassiveQueryJSON(args[0], filter); err != nil {
			logger.Error("Error: %v", err)
			os.Exit(1)
		}
	},
}

func printPassiveQueryJSON(path string, filter passive.QueryFilter) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	_ = file.Close()

	fmt.Println("[")
	first := true
	err = passive.QueryEach(path, filter, func(record passive.Record) error {
		if !first {
			fmt.Println(",")
		}
		first = false
		data, marshalErr := json.MarshalIndent(record, "  ", "  ")
		if marshalErr != nil {
			return marshalErr
		}
		fmt.Print("  ")
		fmt.Print(strings.ReplaceAll(string(data), "\n", "\n  "))
		return nil
	})
	if err != nil {
		return err
	}
	if !first {
		fmt.Println()
	}
	fmt.Println("]")
	return nil
}

var rulesLintCmd = &cobra.Command{
	Use:   "lint [rule-file-or-directory...]",
	Short: "Validate external YAML fingerprint rules",
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			logger.Error("Error: must specify at least one YAML rule file or directory")
			os.Exit(1)
		}
		var loaded []rules.Rule
		for _, path := range args {
			ruleSet, err := rules.LoadYAMLPath(path)
			if err != nil {
				logger.Error("Error: %v", err)
				os.Exit(1)
			}
			loaded = append(loaded, ruleSet...)
		}
		report := rules.LintRules(loaded)
		printLintReport(report)
		if report.HasErrors() {
			os.Exit(1)
		}
		logger.Success("Rules lint passed. rules=%d products=%d warnings=%d", report.Rules, report.Products, len(report.Warnings))
	},
}

var rulesCompileCmd = &cobra.Command{
	Use:   "compile [rule-file-or-directory...]",
	Short: "Validate YAML rules for runtime loading",
	Run: func(cmd *cobra.Command, args []string) {
		rulesLintCmd.Run(cmd, args)
		fmt.Println("External YAML rules are loaded directly at runtime; built-in rules are compiled into the binary during release builds.")
	},
}

var rulesTestCmd = &cobra.Command{
	Use:   "test [rule-file-or-directory...]",
	Short: "Run fixture replay tests for external YAML rules",
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			logger.Error("Error: must specify at least one YAML rule file or directory")
			os.Exit(1)
		}
		var loaded []rules.Rule
		for _, path := range args {
			ruleSet, err := rules.LoadYAMLPath(path)
			if err != nil {
				logger.Error("Error: %v", err)
				os.Exit(1)
			}
			loaded = append(loaded, ruleSet...)
		}
		report := rules.LintRules(loaded)
		printLintReport(report)
		failures := rules.TestRules(loaded)
		for _, failure := range failures {
			logger.Error("Rule test failed: [%s] %s", failure.RuleID, failure.Message)
		}
		if report.HasErrors() || len(failures) > 0 {
			os.Exit(1)
		}
		logger.Success("Rules test passed. rules=%d products=%d fixtures=%d", report.Rules, report.Products, countFixtures(loaded))
	},
}

var rulesStatsCmd = &cobra.Command{
	Use:   "stats",
	Short: "Show built-in and loaded rule statistics",
	Run: func(cmd *cobra.Command, args []string) {
		rulePaths, _ := cmd.Root().Flags().GetStringArray("rules")
		if err := rules.Init(rulePaths); err != nil {
			logger.Error("Error: Failed to load fingerprint rules: %v", err)
			os.Exit(1)
		}
		report := rules.Stats(rules.ActiveRules())
		fmt.Printf("rules=%d products=%d\n", report.Rules, report.Products)
		fmt.Printf("lint.errors=%d\n", report.LintErrors)
		fmt.Printf("lint.warnings=%d\n", report.LintWarnings)
		printStatsMap("tier.", report.Tiers)
		printStatsMap("lint.errors.tier.", report.LintErrorsByTier)
		printStatsMap("lint.warnings.tier.", report.LintWarningsByTier)
		categories := make([]string, 0, len(report.Categories))
		for category := range report.Categories {
			categories = append(categories, category)
		}
		sort.Strings(categories)
		for _, category := range categories {
			fmt.Printf("%s=%d\n", category, report.Categories[category])
		}
	},
}

var rulesDoctorCmd = &cobra.Command{
	Use:   "doctor [rule-file-or-directory...]",
	Short: "Summarize rule quality issues and remediation priorities",
	Run: func(cmd *cobra.Command, args []string) {
		maxRules, _ := cmd.Flags().GetInt("max-rules")
		var ruleSet []rules.Rule
		if len(args) == 0 {
			rulePaths, _ := cmd.Root().Flags().GetStringArray("rules")
			if err := rules.Init(rulePaths); err != nil {
				logger.Error("Error: Failed to load fingerprint rules: %v", err)
				os.Exit(1)
			}
			ruleSet = rules.ActiveRules()
		} else {
			for _, path := range args {
				loaded, err := rules.LoadYAMLPath(path)
				if err != nil {
					logger.Error("Error: %v", err)
					os.Exit(1)
				}
				ruleSet = append(ruleSet, loaded...)
			}
		}
		report := rules.Doctor(ruleSet, maxRules)
		printDoctorReport(report)
		if report.Stats.LintErrors > 0 {
			os.Exit(1)
		}
	},
}

func printStatsMap(prefix string, values map[string]int) {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		fmt.Printf("%s%s=%d\n", prefix, key, values[key])
	}
}

func printDoctorReport(report rules.DoctorReport) {
	fmt.Printf("rules=%d products=%d\n", report.Stats.Rules, report.Stats.Products)
	fmt.Printf("lint.errors=%d\n", report.Stats.LintErrors)
	fmt.Printf("lint.warnings=%d\n", report.Stats.LintWarnings)
	printStatsMap("tier.", report.Stats.Tiers)
	printStatsMap("lint.errors.tier.", report.Stats.LintErrorsByTier)
	printStatsMap("lint.warnings.tier.", report.Stats.LintWarningsByTier)
	for i, issue := range report.Issues {
		fmt.Printf("issue.%d.severity=%s\n", i+1, issue.Severity)
		fmt.Printf("issue.%d.count=%d\n", i+1, issue.Count)
		fmt.Printf("issue.%d.message=%s\n", i+1, issue.Message)
	}
	for _, rule := range report.Rules {
		fmt.Printf("rule=%s tier=%s category=%s errors=%d warnings=%d name=%q\n", rule.RuleID, rule.Tier, rule.Category, rule.Errors, rule.Warnings, rule.Name)
		for _, suggestion := range rule.Suggestions {
			fmt.Printf("  suggestion=%s\n", suggestion)
		}
	}
	if report.HasMore {
		fmt.Println("more=true")
	}
}

func countRuleProducts(ruleSet []rules.Rule) int {
	seen := map[string]struct{}{}
	for _, rule := range ruleSet {
		seen[rule.Name] = struct{}{}
	}
	return len(seen)
}

func countFixtures(ruleSet []rules.Rule) int {
	count := 0
	for _, rule := range ruleSet {
		count += len(rule.Examples.Positive)
		count += len(rule.Examples.Negative)
	}
	return count
}

func printLintReport(report rules.LintReport) {
	for _, item := range report.Errors {
		logger.Error("Rule lint error: [%s] %s", item.RuleID, item.Message)
	}
	for _, item := range report.Warnings {
		logger.Warn("Rule lint warning: [%s] %s", item.RuleID, item.Message)
	}
}

func init() {
	rulesCmd.AddCommand(rulesLintCmd)
	rulesCmd.AddCommand(rulesCompileCmd)
	rulesCmd.AddCommand(rulesTestCmd)
	rulesCmd.AddCommand(rulesStatsCmd)
	rulesDoctorCmd.Flags().Int("max-rules", 20, "Maximum number of rule remediation entries to print; 0 prints summary only")
	rulesCmd.AddCommand(rulesDoctorCmd)

	passiveQueryCmd.Flags().String("url", "", "Filter by URL substring")
	passiveQueryCmd.Flags().String("cms", "", "Filter by product name")
	passiveQueryCmd.Flags().String("category", "", "Filter by category")
	passiveQueryCmd.Flags().Int("min-confidence", 0, "Filter by minimum confidence")
	passiveQueryCmd.Flags().Int("limit", 0, "Limit returned passive records")
	passiveCmd.AddCommand(passiveQueryCmd)

	tlsCmd.AddCommand(tlsCapabilitiesCmd)
	devCmd.AddCommand(devReleaseCheckCmd)
}

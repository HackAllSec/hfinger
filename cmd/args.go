package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"hfinger/config"
	"hfinger/logger"
	"hfinger/models"
	"hfinger/output"
	"hfinger/passive"
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
		thread, _ := cmd.Flags().GetInt("thread")
		redirect, _ := cmd.Flags().GetInt("redirect")
		outputJSON, _ := cmd.Flags().GetString("output-json")
		outputXML, _ := cmd.Flags().GetString("output-xml")
		outputXLSX, _ := cmd.Flags().GetString("output-xlsx")
		rulePaths, _ := cmd.Flags().GetStringArray("rules")
		passiveStore, _ := cmd.Flags().GetString("passive-store")
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

		utils.ConfigureClientCertificates(clientCert, clientKey, gmClientCert, gmClientKey)
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
	RootCmd.Flags().String("gm-client-cert", "", "GM/TLS client certificate for mutual TLS targets")
	RootCmd.Flags().String("gm-client-key", "", "GM/TLS client private key for mutual TLS targets")
	RootCmd.Flags().StringArray("rules", nil, "Load external YAML rule file or directory; can be specified multiple times")
	RootCmd.Flags().String("passive-store", "", "Write passive mode fingerprint results to a JSONL file")
	RootCmd.Flags().IntP("thread", "t", 100, "Number of fingerprint recognition threads")
	RootCmd.Flags().IntP("redirect", "r", 5, "Number of max redirects")
	RootCmd.Flags().BoolP("check-update", "c", false, "Check for updates and upgrades")
	RootCmd.Flags().BoolP("update", "", false, "Show rule update guidance")
	RootCmd.Flags().BoolP("upgrade", "", false, "Upgrade to the latest version")
	RootCmd.Flags().BoolP("version", "v", false, "Display the current version of the tool")

	RootCmd.AddCommand(rulesCmd)
	RootCmd.AddCommand(passiveCmd)
}

var rulesCmd = &cobra.Command{
	Use:   "rules",
	Short: "Manage external YAML fingerprint rules",
}

var passiveCmd = &cobra.Command{
	Use:   "passive",
	Short: "Query passive mode JSONL results",
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
		records, err := passive.Query(args[0], passive.QueryFilter{
			URL:           urlFilter,
			CMS:           cmsFilter,
			Category:      categoryFilter,
			MinConfidence: minConfidence,
		})
		if err != nil {
			logger.Error("Error: %v", err)
			os.Exit(1)
		}
		data, err := json.MarshalIndent(records, "", "  ")
		if err != nil {
			logger.Error("Error: %v", err)
			os.Exit(1)
		}
		fmt.Println(string(data))
	},
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

	passiveQueryCmd.Flags().String("url", "", "Filter by URL substring")
	passiveQueryCmd.Flags().String("cms", "", "Filter by product name")
	passiveQueryCmd.Flags().String("category", "", "Filter by category")
	passiveQueryCmd.Flags().Int("min-confidence", 0, "Filter by minimum confidence")
	passiveCmd.AddCommand(passiveQueryCmd)
}

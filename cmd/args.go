package cmd

import (
    "github.com/spf13/cobra"
    "github.com/fatih/color"
    "os"
    "time"

    "hfinger/config"
    "hfinger/logger"
    "hfinger/output"
    "hfinger/models"
    "hfinger/utils"
)

var RootCmd = &cobra.Command{
    Use:   "hfinger",
    Short: "A high-performance command-line tool for web framework, CDN and CMS fingerprinting",
    Run: func(cmd *cobra.Command, args []string) {
        url, _ := cmd.Flags().GetString("url")
        file, _ := cmd.Flags().GetString("file")
        listen,_ := cmd.Flags().GetString("listen")
        
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
        listen,_ := cmd.Flags().GetString("listen")
        proxy, _ := cmd.Flags().GetString("proxy")
        thread, _ := cmd.Flags().GetInt("thread")
        redirect, _ := cmd.Flags().GetInt("redirect")
        outputJSON, _ := cmd.Flags().GetString("output-json")
        outputXML, _ := cmd.Flags().GetString("output-xml")
        outputXLSX, _ := cmd.Flags().GetString("output-xlsx")
        versionFlag, _ := cmd.Flags().GetBool("version")
        checkFlag,_ := cmd.Flags().GetBool("check-update")
        updateFlag,_ := cmd.Flags().GetBool("update")
        upgradeFlag,_ := cmd.Flags().GetBool("upgrade")
        
        if versionFlag {
            color.Green("hfinger version: %s", config.Version)
            os.Exit(0)
        }

        if redirect < 1 {
            logger.Error("Error: The number of redirect cannot be less than 1.")
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

        if url == "" && file == "" && listen == "" {
            cmd.Help()
            logger.Error("Error: Must specify one of the -u, -f, or -l parameters!")
            os.Exit(1)
        }
        if url != "" && file != "" && listen != "" {
            logger.Error("Error: You can only choose one of the -u, -f or -l parameters!")
            os.Exit(1)
        }
        if url != "" {
            _, err := utils.GetBaseURL(url)
            if err != nil {
                logger.Error("Error: %v",err)
            }
        }
        
        if !config.Isconfig {
            logger.Error("Error: Failed to load fingerprint library.You can use --update option to get fingerprint library.")
            os.Exit(1)
        }
        models.ShowFingerPrints()
        if thread < 1 {
            logger.Error("Error: The number of threads cannot be less than 1.")
            os.Exit(1)
        }
        models.SetThread(thread)
        models.SetMaxRedirects(redirect)
        if outputJSON != "" {
            err = output.SetOutput("json",outputJSON)
        }
        if outputXML != "" {
            err = output.SetOutput("xml",outputXML)
        }
        if outputXLSX != "" {
            err = output.SetOutput("xlsx",outputXLSX)
        }
        if err != nil {
            logger.Error("Error: %v", err)
        }
    },
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
    RootCmd.Flags().IntP("thread", "t", 100, "Number of fingerprint recognition threads")
    RootCmd.Flags().IntP("redirect", "r", 5, "Number of max redirects")
    RootCmd.Flags().BoolP("check-update", "c", false, "Check for updates and upgrades")
    RootCmd.Flags().BoolP("update", "", false, "Update fingerprint database")
    RootCmd.Flags().BoolP("upgrade", "", false, "Upgrade to the latest version")
    RootCmd.Flags().BoolP("version", "v", false, "Display the current version of the tool")
}

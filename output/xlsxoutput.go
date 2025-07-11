package output

import (
    "github.com/tealeg/xlsx"
    "hfinger/config"
    "strconv"
    "strings"
)

func sanitizeSheetName(name string) string {
    const maxLen = 31
    invalidChars := ":*?/[]\\`,;\"|"
    
    // 替换非法字符为空格
    for _, c := range invalidChars {
        name = strings.ReplaceAll(name, string(c), "")
    }

    // 截断到最大长度
    if len(name) > maxLen {
        name = name[:maxLen]
    }

    return name
}

func WriteXLSXOutput(filename string, results []config.Result) error {
    file := xlsx.NewFile()
    
    // 创建 "Results" 汇总 sheet
    summarySheet, err := file.AddSheet("Results")
    if err != nil {
        return err
    }

    // 添加表头
    header := summarySheet.AddRow()
    header.AddCell().Value = "URL"
    header.AddCell().Value = "CMS"
    header.AddCell().Value = "Server"
    header.AddCell().Value = "StatusCode"
    header.AddCell().Value = "Title"

    // 创建一个 map，用于按 CMS 分类存储结果
    cmsSheets := make(map[string]*xlsx.Sheet)

    for _, result := range results {
        // 添加到汇总表
        row := summarySheet.AddRow()
        row.AddCell().Value = result.URL
        row.AddCell().Value = result.CMS
        row.AddCell().Value = result.Server
        row.AddCell().Value = strconv.Itoa(result.StatusCode)
        row.AddCell().Value = result.Title

        // 按 CMS 创建新 sheet，并添加记录
        if _, exists := cmsSheets[result.CMS]; !exists {
            safeCMSName := sanitizeSheetName(result.CMS)
            cmsSheet, err := file.AddSheet(safeCMSName)
            if err != nil {
                return err
            }
            cmsSheets[result.CMS] = cmsSheet

            // 为新 sheet 添加表头
            cmsHeader := cmsSheet.AddRow()
            cmsHeader.AddCell().Value = "URL"
            cmsHeader.AddCell().Value = "Server"
            cmsHeader.AddCell().Value = "StatusCode"
            cmsHeader.AddCell().Value = "Title"
        }

        // 添加到 CMS 分类表
        cmsRow := cmsSheets[result.CMS].AddRow()
        cmsRow.AddCell().Value = result.URL
        cmsRow.AddCell().Value = result.Server
        cmsRow.AddCell().Value = strconv.Itoa(result.StatusCode)
        cmsRow.AddCell().Value = result.Title
    }

    return file.Save(filename)
}

package output

import (
    "github.com/tealeg/xlsx"
    "hfinger/config"
    "strconv"
)

func WriteXLSXOutput(filename string, results []config.Result) error {
    file := xlsx.NewFile()
    sheet, err := file.AddSheet("Results")
    if err != nil {
        return err
    }

    header := sheet.AddRow()
    header.AddCell().Value = "URL"
    header.AddCell().Value = "CMS"
    header.AddCell().Value = "Server"
    header.AddCell().Value = "StatusCode"
    header.AddCell().Value = "Title"

    for _, result := range results {
        row := sheet.AddRow()
        row.AddCell().Value = result.URL
        row.AddCell().Value = result.CMS
        row.AddCell().Value = result.Server
        row.AddCell().Value = strconv.Itoa(result.StatusCode)
        row.AddCell().Value = result.Title
    }

    return file.Save(filename)
}

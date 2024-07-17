package output

import (
    "encoding/xml"
    "hfinger/config"
    "os"
)

func WriteXMLOutput(filename string, results []config.Result) error {
    file, err := os.Create(filename)
    if err != nil {
        return err
    }
    defer file.Close()

    encoder := xml.NewEncoder(file)
    encoder.Indent("", "  ")

    type ResultList struct {
        XMLName xml.Name        `xml:"results"`
        Results []config.Result `xml:"result"`
    }
    
    resultList := ResultList{Results: results}

    if err := encoder.Encode(resultList); err != nil {
        return err
    }

    return nil
}

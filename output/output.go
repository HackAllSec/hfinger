package output

import (
    "fmt"

    "hfinger/config"
)

var (
    filetype string
    filepath string
    results     []config.Result
)

func SetOutput(format string, path string) error {
    switch format {
    case "json":
        filetype = "json"
    case "xml":
        filetype = "xml"
    case "xlsx":
        filetype = "xlsx"
    default:
        return fmt.Errorf("This type of file is not supported: %s", format)
    }
    filepath = path
    return nil
}

func GetOutput() (string, string) {
    return filetype, filepath
}

func WriteOutputs() error {
    switch filetype {
    case "json":
        if err := WriteJSONOutput(filepath, results); err != nil {
            return err
        }
    case "xml":
        if err := WriteXMLOutput(filepath, results); err != nil {
            return err
        }
    case "xlsx":
        if err := WriteXLSXOutput(filepath, results); err != nil {
            return err
        }
    default:
        return fmt.Errorf("This type of file is not supported: %s", filetype)
    }
    return nil
}

func AddResults(result config.Result) {
    results = append(results, result)
}

func GetResults() []config.Result {
    return results
}

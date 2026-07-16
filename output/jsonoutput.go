package output

import (
	"encoding/json"
	"hfinger/config"
	"os"
)

func WriteJSONOutput(filename string, results []config.Result) error {
	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filename, data, 0644)
}

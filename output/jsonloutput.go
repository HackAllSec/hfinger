package output

import (
	"encoding/json"
	"os"

	"hfinger/config"
)

func WriteJSONLOutput(filename string, results []config.Result) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	for _, result := range results {
		if err := encoder.Encode(result); err != nil {
			return err
		}
	}
	return nil
}

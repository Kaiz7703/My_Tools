package efficacy

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type PayloadLoader struct {
	dataPath string
}

func NewPayloadLoader(dataPath string) *PayloadLoader {
	return &PayloadLoader{dataPath: dataPath}
}

func (pl *PayloadLoader) LoadAll() (map[string][]Payload, error) {
	datasets := make(map[string][]Payload)

	err := filepath.Walk(pl.dataPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() && filepath.Ext(path) == ".json" {
			payloads, err := pl.loadFile(path)
			if err != nil {
				return fmt.Errorf("failed to load %s: %w", path, err)
			}

			testName := filepath.Base(path)
			testName = testName[:len(testName)-5] // Remove .json
			datasets[testName] = payloads
		}

		return nil
	})

	return datasets, err
}

func (pl *PayloadLoader) loadFile(path string) ([]Payload, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var payloads []Payload
	if err := json.Unmarshal(data, &payloads); err != nil {
		return nil, err
	}

	return payloads, nil
}

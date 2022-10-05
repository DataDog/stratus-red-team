package main

import (
	"os"

	"gopkg.in/yaml.v3"
)

func GenerateYAML(path string, index interface{}) error {
	// if file doesn't exist, it creates. Truncates file and open it in write only mode.
	yamlFile, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer yamlFile.Close()

	enconder := yaml.NewEncoder(yamlFile)
	defer enconder.Close()

	if err := enconder.Encode(&index); err != nil {
		return err
	}
	return nil
}

package runner

import (
	"errors"
	"github.com/datadog/stratus-red-team/internal/state"
	"github.com/datadog/stratus-red-team/internal/utils"
	"github.com/datadog/stratus-red-team/pkg/attacktechnique"
	"github.com/hashicorp/terraform-exec/tfexec"
	"log"
	"os"
	"path/filepath"
)

func extractTerraformFile(technique *attacktechnique.AttackTechnique) (string, error) {
	dir := state.GetStateDirectory()
	terraformDir := filepath.Join(dir, technique.Name)
	terraformFilePath := filepath.Join(terraformDir, "main.tf")
	if utils.FileExists(terraformDir) {
		return terraformDir, nil
	}
	err := os.Mkdir(terraformDir, 0744)
	if err != nil {
		return "", err
	}

	err = os.WriteFile(terraformFilePath, technique.PrerequisitesTerraformCode, 0644)
	if err != nil {
		return "", err
	}

	return terraformDir, nil
}

func WarmUp(technique *attacktechnique.AttackTechnique, warmup bool) (*tfexec.Terraform, error) {
	terraformDir, err := extractTerraformFile(technique)
	if err != nil {
		return nil, err
	}

	// If we don't want to warm up the technique, just return the Terraform handle that will allow
	// for a destroy later on
	if !warmup {
		return TerraformHandleForDirectory(terraformDir)
	}

	log.Println("Spinning up pre-requisites")
	terraformHandle, err := TerraformApply(terraformDir)
	if err != nil {
		return nil, errors.New("Unable to run terraform apply on pre-requisite: " + err.Error())
	}
	return terraformHandle, nil
}

func RunAttackTechnique(technique *attacktechnique.AttackTechnique, cleanup bool, warmup bool) error {
	terraformHandle, err := WarmUp(technique, warmup)
	if err != nil {
		return err
	}

	// Detonate
	err = technique.Detonate(map[string]string{})
	if cleanup {
		defer func() {
			if technique.Cleanup != nil {
				technique.Cleanup()
			}
			log.Println("Cleaning up with terraform destroy")
			TerraformDestroy(terraformHandle)
		}()
	}
	if err != nil {
		return errors.New("Error while detonating attack technique " + technique.Name + ": " + err.Error())
	}

	return nil
}

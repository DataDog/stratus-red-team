package runner

import (
	"context"
	"errors"
	"github.com/datadog/stratus-red-team/internal/utils"
	"github.com/hashicorp/go-version"
	"github.com/hashicorp/hc-install/product"
	"github.com/hashicorp/hc-install/releases"
	"github.com/hashicorp/terraform-exec/tfexec"
	"log"
	"os"
	"path"
)

const TerraformVersion = "1.1.2"

type TerraformManager struct {
	terraformBinaryPath string
	terraformVersion    string
}

func NewTerraformManager(terraformBinaryPath string) *TerraformManager {
	manager := TerraformManager{
		terraformVersion:    TerraformVersion,
		terraformBinaryPath: terraformBinaryPath,
	}
	manager.initialize()
	return &manager
}

func (m *TerraformManager) initialize() {
	// Download the Terraform binary if it doesn't exist already
	if !utils.FileExists(m.terraformBinaryPath) {
		terraformInstaller := &releases.ExactVersion{
			Product:                  product.Terraform,
			Version:                  version.Must(version.NewVersion(TerraformVersion)),
			InstallDir:               m.terraformBinaryPath,
			SkipChecksumVerification: false,
		}
		log.Println("Installing Terraform")
		_, err := terraformInstaller.Install(context.Background())
		if err != nil {
			log.Fatalf("error installing Terraform: %s", err)
		}
	}
}

func (m *TerraformManager) TerraformInitAndApply(directory string) (map[string]string, error) {
	terraform, err := tfexec.NewTerraform(directory, m.terraformBinaryPath)
	terraformInitializedFile := path.Join(directory, ".terraform-initialized")
	if !utils.FileExists(terraformInitializedFile) {
		log.Println("Initializing Terraform")
		err = terraform.Init(context.Background())
		if err != nil {
			return nil, errors.New("unable to initialize Terraform: " + err.Error())
		}
		os.Create(terraformInitializedFile)

	}

	log.Println("Applying Terraform")
	err = terraform.Apply(context.Background(), tfexec.Refresh(false))
	if err != nil {
		return nil, errors.New("unable to apply Terraform: " + err.Error())
	}

	rawOutputs, _ := terraform.Output(context.Background())
	outputs := make(map[string]string, len(rawOutputs))
	for outputName, outputRawValue := range rawOutputs {
		outputValue := string(outputRawValue.Value)
		// Strip the first and last quote which gets added for some reason
		outputValue = outputValue[1 : len(outputValue)-1]
		outputs[outputName] = outputValue
	}
	return outputs, nil
}

func (m *TerraformManager) TerraformDestroy(directory string) error {
	terraform, err := tfexec.NewTerraform(directory, m.terraformBinaryPath)
	if err != nil {
		return err
	}

	log.Println("Destroying Terraform")
	return terraform.Destroy(context.Background())
}

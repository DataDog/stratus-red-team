package runner

import (
	"context"
	"errors"
	"github.com/datadog/stratus-red-team/v2/internal/utils"
	"github.com/hashicorp/go-version"
	"github.com/hashicorp/hc-install/product"
	"github.com/hashicorp/hc-install/releases"
	"github.com/hashicorp/terraform-exec/tfexec"
	"log"
	"os"
	"path"
	"path/filepath"
)

const TerraformVersion = "1.1.2"

type TerraformManager interface {
	Initialize()
	TerraformInitAndApply(directory string) (map[string]string, error)
	TerraformDestroy(directory string) error
}

type TerraformManagerImpl struct {
	terraformBinaryPath string
	terraformVersion    string
	terraformUserAgent  string
	context             context.Context
}

func NewTerraformManager(terraformBinaryPath string, userAgent string) TerraformManager {
	return NewTerraformManagerWithContext(context.Background(), terraformBinaryPath, userAgent)
}

func NewTerraformManagerWithContext(ctx context.Context, terraformBinaryPath string, userAgent string) TerraformManager {
	manager := TerraformManagerImpl{
		terraformVersion:    TerraformVersion,
		terraformBinaryPath: terraformBinaryPath,
		terraformUserAgent:  userAgent,
		context:             ctx,
	}
	manager.Initialize()
	return &manager
}

func (m *TerraformManagerImpl) Initialize() {
	// Download the Terraform binary if it doesn't exist already
	if !utils.FileExists(m.terraformBinaryPath) {
		terraformInstaller := &releases.ExactVersion{
			Product:                  product.Terraform,
			Version:                  version.Must(version.NewVersion(TerraformVersion)),
			InstallDir:               filepath.Dir(m.terraformBinaryPath),
			SkipChecksumVerification: false,
		}
		log.Println("Installing Terraform in " + m.terraformBinaryPath)
		_, err := terraformInstaller.Install(m.context)
		if err != nil {
			log.Fatalf("error installing Terraform: %s", err)
		}
	}
}

func (m *TerraformManagerImpl) TerraformInitAndApply(directory string) (map[string]string, error) {
	terraform, err := tfexec.NewTerraform(directory, m.terraformBinaryPath)
	if err != nil {
		return map[string]string{}, errors.New("unable to instantiate Terraform: " + err.Error())
	}

	err = terraform.SetAppendUserAgent(m.terraformUserAgent)
	if err != nil {
		return map[string]string{}, errors.New("unable to configure Terraform: " + err.Error())
	}

	terraformInitializedFile := path.Join(directory, ".terraform-initialized")
	if !utils.FileExists(terraformInitializedFile) {
		log.Println("Initializing Terraform to spin up technique prerequisites")
		err = terraform.Init(m.context)
		if err != nil {
			return nil, errors.New("unable to Initialize Terraform: " + err.Error())
		}

		_, err = os.Create(terraformInitializedFile)
		if err != nil {
			return nil, errors.New("unable to initialize Terraform: " + err.Error())
		}

	}

	log.Println("Applying Terraform to spin up technique prerequisites")
	err = terraform.Apply(m.context, tfexec.Refresh(false))
	if err != nil {
		return nil, errors.New("unable to apply Terraform: " + err.Error())
	}

	rawOutputs, _ := terraform.Output(m.context)
	outputs := make(map[string]string, len(rawOutputs))
	for outputName, outputRawValue := range rawOutputs {
		outputValue := string(outputRawValue.Value)
		// Strip the first and last quote which gets added for some reason
		outputValue = outputValue[1 : len(outputValue)-1]
		outputs[outputName] = outputValue
	}
	return outputs, nil
}

func (m *TerraformManagerImpl) TerraformDestroy(directory string) error {
	terraform, err := tfexec.NewTerraform(directory, m.terraformBinaryPath)
	if err != nil {
		return err
	}

	return terraform.Destroy(m.context)
}

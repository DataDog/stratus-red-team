package runner

import (
	"context"
	"errors"
	"log"
	"os"
	"path"
	"path/filepath"

	"github.com/datadog/stratus-red-team/v2/internal/utils"
	"github.com/hashicorp/go-version"
	"github.com/hashicorp/hc-install/product"
	"github.com/hashicorp/hc-install/releases"
	"github.com/hashicorp/terraform-exec/tfexec"
)

const TerraformVersion = "1.3.10"

type TerraformManager interface {
	Initialize()
	TerraformInitAndApply(directory string, variables map[string]string) (map[string]string, error)
	TerraformDestroy(directory string, variables map[string]string) error
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
	if utils.FileExists(m.terraformBinaryPath) {
		if m.existingBinaryVersionSufficient() {
			return
		}
		log.Printf("Terraform binary at %s is below required version %s, downloading the correct version", m.terraformBinaryPath, m.terraformVersion)
	}

	terraformInstaller := &releases.ExactVersion{
		Product:                  product.Terraform,
		Version:                  version.Must(version.NewVersion(TerraformVersion)),
		InstallDir:               filepath.Dir(m.terraformBinaryPath),
		SkipChecksumVerification: false,
	}
	_, err := terraformInstaller.Install(m.context)
	if err != nil {
		log.Fatalf("error installing Terraform: %s", err)
	}
}

func (m *TerraformManagerImpl) TerraformInitAndApply(directory string, variables map[string]string) (map[string]string, error) {
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
	applyOptions := []tfexec.ApplyOption{tfexec.Refresh(false)}
	for key, value := range variables {
		applyOptions = append(applyOptions, tfexec.Var(key+"="+value))
	}
	err = terraform.Apply(m.context, applyOptions...)
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

func (m *TerraformManagerImpl) TerraformDestroy(directory string, variables map[string]string) error {
	terraform, err := tfexec.NewTerraform(directory, m.terraformBinaryPath)
	if err != nil {
		return err
	}

	destroyOptions := []tfexec.DestroyOption{}
	for key, value := range variables {
		destroyOptions = append(destroyOptions, tfexec.Var(key+"="+value))
	}
	return terraform.Destroy(m.context, destroyOptions...)
}

// existingBinaryVersionSufficient checks whether the terraform binary at terraformBinaryPath has a
// version >= TerraformVersion. Returns false if the version cannot be determined.
func (m *TerraformManagerImpl) existingBinaryVersionSufficient() bool {
	// tfexec needs a working directory
	tmpDir, err := os.MkdirTemp("", "stratus-tf-version-check")
	if err != nil {
		return false
	}
	defer os.RemoveAll(tmpDir)

	tf, err := tfexec.NewTerraform(tmpDir, m.terraformBinaryPath)
	if err != nil {
		return false
	}

	installedVersion, _, err := tf.Version(m.context, true)
	if err != nil {
		return false
	}

	requiredVersion := version.Must(version.NewVersion(m.terraformVersion))
	return installedVersion.GreaterThanOrEqual(requiredVersion)
}

package runner

import (
	"context"
	"github.com/datadog/stratus-red-team/internal/state"
	"github.com/datadog/stratus-red-team/internal/utils"
	"github.com/hashicorp/go-version"
	"github.com/hashicorp/hc-install/product"
	"github.com/hashicorp/hc-install/releases"
	"github.com/hashicorp/terraform-exec/tfexec"
	"log"
	"path/filepath"
)

var terraformBinaryPath string

const TerraformVersion = "1.1.2"

func init() {
	// Download the Terraform binary if it doesn't exist already
	terraformBinaryPath = filepath.Join(state.GetStateDirectory(), "terraform")
	if !utils.FileExists(terraformBinaryPath) {
		terraformInstaller := &releases.ExactVersion{
			Product:                  product.Terraform,
			Version:                  version.Must(version.NewVersion(TerraformVersion)),
			InstallDir:               state.GetStateDirectory(),
			SkipChecksumVerification: false,
		}
		log.Println("Installing Terraform")
		_, err := terraformInstaller.Install(context.Background())
		if err != nil {
			log.Fatalf("error installing Terraform: %s", err)
		}
	}
}

func TerraformApply(directory string) (*tfexec.Terraform, error) {
	tf, err := TerraformHandleForDirectory(directory)
	if err != nil {
		return nil, err
	}

	log.Println("Initializing Terraform")
	tf.Init(context.Background())
	log.Println("Applying Terraform")
	err = tf.Apply(context.Background())
	if err != nil {
		return nil, err
	}

	return tf, nil
}

func TerraformHandleForDirectory(directory string) (*tfexec.Terraform, error) {
	return tfexec.NewTerraform(directory, terraformBinaryPath)
}

func TerraformDestroy(terraform *tfexec.Terraform) error {
	log.Println("Destroying Terraform")
	return terraform.Destroy(context.Background())
}

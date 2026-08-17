package runner

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/datadog/stratus-red-team/v2/internal/state"
	"github.com/datadog/stratus-red-team/v2/internal/utils"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/log"
	"github.com/hashicorp/go-version"
	"github.com/hashicorp/hc-install/product"
	"github.com/hashicorp/hc-install/releases"
	"github.com/hashicorp/terraform-exec/tfexec"
)

const TerraformVersion = "1.3.10"

// pluginCacheEnvVar tells Terraform where to cache provider plugins across working directories.
const pluginCacheEnvVar = "TF_PLUGIN_CACHE_DIR"

// Terraform plugin cache initialization is not concurrency safe, so we gate terraform init with a mutex.
var terraformInitMutex sync.Mutex

type TerraformManager interface {
	Initialize()
	TerraformInitAndApply(directory string, variables map[string]string) (map[string]string, error)
	TerraformDestroy(directory string, variables map[string]string) error
}

type TerraformManagerImpl struct {
	terraformBinaryPath  string
	terraformVersion     string
	terraformUserAgent   string
	backendConfigs       map[string]string
	pluginCacheDirectory string
	context              context.Context
}

// TerraformManagerOption configures optional overrides on a TerraformManagerImpl.
type TerraformManagerOption func(*TerraformManagerImpl)

// WithBackendConfigs sets key=value pairs passed as -backend-config flags during terraform init.
// Used to inject S3 backend credentials without writing them to disk.
func WithBackendConfigs(configs map[string]string) TerraformManagerOption {
	return func(m *TerraformManagerImpl) { m.backendConfigs = configs }
}

// WithPluginCacheDirectory sets a provider plugin cache shared by every working directory, enabling
// each execution to use that rather than downloading its own copy of the providers.
//
// directory must be an absolute path.
func WithPluginCacheDirectory(directory string) TerraformManagerOption {
	return func(m *TerraformManagerImpl) { m.pluginCacheDirectory = directory }
}

func NewTerraformManager(terraformBinaryPath string, userAgent string, opts ...TerraformManagerOption) TerraformManager {
	return NewTerraformManagerWithContext(context.Background(), terraformBinaryPath, userAgent, opts...)
}

func NewTerraformManagerWithContext(ctx context.Context, terraformBinaryPath string, userAgent string, opts ...TerraformManagerOption) TerraformManager {
	manager := TerraformManagerImpl{
		terraformVersion:    TerraformVersion,
		terraformBinaryPath: terraformBinaryPath,
		terraformUserAgent:  userAgent,
		context:             ctx,
	}
	for _, opt := range opts {
		opt(&manager)
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
		return map[string]string{}, fmt.Errorf("unable to instantiate Terraform: %w", err)
	}

	if err := m.configureEnvironment(terraform); err != nil {
		return map[string]string{}, fmt.Errorf("unable to configure Terraform environment: %w", err)
	}

	err = terraform.SetAppendUserAgent(m.terraformUserAgent)
	if err != nil {
		return map[string]string{}, fmt.Errorf("unable to configure Terraform: %w", err)
	}

	if err := m.ensureInitialized(terraform, directory); err != nil {
		return nil, fmt.Errorf("unable to initialize Terraform: %w", err)
	}

	log.Println("Applying Terraform to spin up technique prerequisites")
	applyOptions := []tfexec.ApplyOption{tfexec.Refresh(false)}
	for key, value := range variables {
		applyOptions = append(applyOptions, tfexec.Var(key+"="+value))
	}
	err = terraform.Apply(m.context, applyOptions...)
	if err != nil {
		return nil, fmt.Errorf("unable to apply Terraform: %w", err)
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

	if err := m.configureEnvironment(terraform); err != nil {
		return fmt.Errorf("unable to configure Terraform environment: %w", err)
	}

	if err := m.ensureInitialized(terraform, directory); err != nil {
		return fmt.Errorf("unable to initialize Terraform for destroy: %w", err)
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

// configureEnvironment sets the environment Terraform runs with.
//
// tfexec replaces the environment instead of extending it, so we start from our own. Variables
// that Terraform's CLI wrapper reserves (TF_CLI_ARGS, TF_VAR_*, TF_IN_AUTOMATION, ...) are
// dropped by CleanEnv: tfexec rejects them outright, so without this a caller who had any of
// them set would fail the whole run. Log variables are unaffected, tfexec overrides those itself.
func (m *TerraformManagerImpl) configureEnvironment(tf *tfexec.Terraform) error {
	env := map[string]string{}
	for _, entry := range os.Environ() {
		parts := strings.SplitN(entry, "=", 2)
		if len(parts) == 2 {
			env[parts[0]] = parts[1]
		}
	}

	// Terraform reads ARM_SUBSCRIPTION_ID, while the Go Azure SDK reads AZURE_SUBSCRIPTION_ID.
	if env["ARM_SUBSCRIPTION_ID"] == "" && env["AZURE_SUBSCRIPTION_ID"] != "" {
		env["ARM_SUBSCRIPTION_ID"] = env["AZURE_SUBSCRIPTION_ID"]
	}

	if cacheDirectory := m.ensurePluginCacheDirectory(); cacheDirectory != "" {
		env[pluginCacheEnvVar] = cacheDirectory
	}

	return tf.SetEnv(tfexec.CleanEnv(env))
}

// ensurePluginCacheDirectory returns the shared provider plugin cache, creating it if needed.
// Terraform does not create it and errors when it is missing, so a cache we cannot create is
// skipped rather than failing the run.
func (m *TerraformManagerImpl) ensurePluginCacheDirectory() string {
	if m.pluginCacheDirectory == "" {
		return ""
	}
	if err := os.MkdirAll(m.pluginCacheDirectory, 0744); err != nil {
		log.Warnf("unable to create the Terraform plugin cache directory %s, continuing without a shared cache: %s", m.pluginCacheDirectory, err.Error())
		return ""
	}
	return m.pluginCacheDirectory
}

// ensureInitialized runs terraform init if not already done in this working directory.
// Backend config credentials are passed via -backend-config flags, keeping secrets off disk.
func (m *TerraformManagerImpl) ensureInitialized(tf *tfexec.Terraform, directory string) error {
	markerFile := filepath.Join(directory, state.StratusStateTerraformInitializedFileName)
	if utils.FileExists(markerFile) {
		return nil
	}

	terraformInitMutex.Lock()
	defer terraformInitMutex.Unlock()

	log.Println("Initializing Terraform")
	var initOpts []tfexec.InitOption
	for key, value := range m.backendConfigs {
		initOpts = append(initOpts, tfexec.BackendConfig(key+"="+value))
	}

	if err := tf.Init(m.context, initOpts...); err != nil {
		return err
	}

	return os.WriteFile(markerFile, nil, 0644)
}

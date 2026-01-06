BUILD_VERSION := dev-snapshot
TECHNIQUE_IMPORTS ?=

MAKEFILE_PATH := $(abspath $(lastword $(MAKEFILE_LIST)))
ROOT_DIR := $(dir $(MAKEFILE_PATH))

# Use go modules
export GO111MODULE=on

# Define binaries directory
BIN_DIR := $(ROOT_DIR)/bin

# Determine which providers are needed based on TECHNIQUE_IMPORTS
# If TECHNIQUE_IMPORTS is empty, use allproviders tag (default behavior)
# Otherwise, parse the imports to determine required providers
ifeq ($(strip $(TECHNIQUE_IMPORTS)),)
    BUILD_TAGS := allproviders
else
    # Extract provider tags from technique imports
    PROVIDERS_NEEDED := $(shell echo "$(TECHNIQUE_IMPORTS)" | tr ',' '\n' | grep -oE '/(aws|azure|gcp|k8s|eks|entra-id)/' | tr -d '/' | sort -u | tr '\n' ',' | sed 's/,$$//')
    # Convert entra-id to entraid for build tag
    PROVIDERS_NEEDED := $(shell echo "$(PROVIDERS_NEEDED)" | sed 's/entra-id/entraid/g')
    BUILD_TAGS := $(PROVIDERS_NEEDED)
endif

# Define go flags
GOFLAGS := -ldflags="-X main.BuildVersion=$(BUILD_VERSION) -w" -tags="$(BUILD_TAGS)"

.PHONY: build docs test thirdparty-licenses mocks

# Default target
all: build

build:
	@echo "Generating technique imports..."
	@cd v2 && TECHNIQUE_IMPORTS="$(TECHNIQUE_IMPORTS)" go generate ./internal/attacktechniques
	@echo "Building Stratus with tags: $(BUILD_TAGS)"
	@cd v2 && go build $(GOFLAGS) -o $(BIN_DIR)/stratus cmd/stratus/*.go
	@echo "Build completed. Binaries are saved in $(BIN_DIR)"

docs:
	@echo "Generating documentation..."
	@cd v2 && go run ./tools/ ../docs
	@echo "Documentation generated successfully."

test:
	@echo "Running tests..."
	@cd v2 && go test ./... -v
	@echo "Tests completed successfully."

thirdparty-licenses:
	@echo "Retrieving third-party licenses..."
	@cd v2 && go get github.com/google/go-licenses
	@cd v2 && go install github.com/google/go-licenses
	@cd v2 && $(GOPATH)/bin/go-licenses csv github.com/datadog/stratus-red-team/v2/cmd/stratus | sort > $(ROOT_DIR)/LICENSE-3rdparty.csv
	@echo "Third-party licenses retrieved and saved to $(ROOT_DIR)/LICENSE-3rdparty.csv"

mocks:
	@echo "Generating mocks..."
	@cd v2 && mockery --name=StateManager --dir internal/state --output internal/state/mocks
	@cd v2 && mockery --name=TerraformManager --dir pkg/stratus/runner --output pkg/stratus/runner/mocks
	@cd v2 && mockery --name=FileSystem --structname FileSystemMock --dir internal/state --output internal/state/mocks
	@echo "Mocks generated successfully."

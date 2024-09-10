BUILD_VERSION := dev-snapshot

MAKEFILE_PATH := $(abspath $(lastword $(MAKEFILE_LIST)))
ROOT_DIR := $(dir $(MAKEFILE_PATH))

# Use go modules
export GO111MODULE=on

# Define binaries directory
BIN_DIR := $(ROOT_DIR)/bin

# Define go flags
GOFLAGS := -ldflags="-X main.BuildVersion=$(BUILD_VERSION)"

.PHONY: build docs test thirdparty-licenses mocks

# Default target
all: build

build:
	@echo "Building Stratus..."
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
	@cd v2 && mockery --name=StateManager --structname StateManagerMock --filename state_manager_mock.go --dir internal/state/manager --output internal/state/manager/ --outpkg manager
	@cd v2 && mockery --name=FileSystem --structname FileSystemMock --filename file_system_mock.go --dir internal/state/filesystem --output internal/state/filesystem --outpkg filesystem
	@cd v2 && mockery --name=DataStore --structname DataStoreMock --filename data_store_mock.go --dir internal/state/datastore --output internal/state/datastore/ --outpkg datastore

	@cd v2 && mockery --name=TerraformManager --dir pkg/stratus/runner --output pkg/stratus/runner/mocks
	@echo "Mocks generated successfully."
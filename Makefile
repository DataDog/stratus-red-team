BUILD_VERSION=dev-snapshot

MAKEFILE_PATH := $(abspath $(lastword $(MAKEFILE_LIST)))
ROOT_DIR := $(dir $(MAKEFILE_PATH))

.PHONY: docs
all: build thirdparty-licenses

build:
	go build -ldflags="-X main.BuildVersion=$(BUILD_VERSION)" -o bin/stratus cmd/stratus/*.go

docs:
	go run tools/generate-techniques-documentation.go

test:
	go test ./... -v

thirdparty-licenses:
	go get github.com/google/go-licenses
	go install github.com/google/go-licenses
	$(GOPATH)/bin/go-licenses csv github.com/datadog/stratus-red-team/cmd/stratus | sort > $(ROOT_DIR)/LICENSE-3rdparty.csv	

mocks:
	mockery --name=StateManager --dir internal/state --output internal/state/mocks
	mockery --name=TerraformManager --dir internal/runner --output internal/runner/mocks
	mockery --name=FileSystem --structname FileSystemMock --dir internal/state --output internal/state/mocks

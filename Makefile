BUILD_VERSION=dev-snapshot

MAKEFILE_PATH := $(abspath $(lastword $(MAKEFILE_LIST)))
ROOT_DIR := $(dir $(MAKEFILE_PATH))

.PHONY: docs
all: build

build:
	cd v2 && go build -ldflags="-X main.BuildVersion=$(BUILD_VERSION)" -o ../bin/stratus cmd/stratus/*.go

docs:
	cd v2 && go run tools/generate-techniques-documentation.go ../docs

test:
	cd v2 && go test ./... -v

thirdparty-licenses:
	go get github.com/google/go-licenses
	go install github.com/google/go-licenses
	cd v2 && $(GOPATH)/bin/go-licenses csv github.com/datadog/stratus-red-team/v2/cmd/stratus | sort > $(ROOT_DIR)/LICENSE-3rdparty.csv

mocks:
	cd v2 && mockery --name=StateManager --dir internal/state --output internal/state/mocks
	cd v2 && mockery --name=TerraformManager --dir pkg/stratus/runner --output pkg/stratus/runner/mocks
	cd v2 && mockery --name=FileSystem --structname FileSystemMock --dir internal/state --output internal/state/mocks
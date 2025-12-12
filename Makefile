.PHONY: build run clean help deps test fmt lint

# Variables
BINARY_NAME=dnsbench
BINARY_PATH=./$(BINARY_NAME).exe
GO=go
GOOS?=$(shell go env GOOS)
GOARCH?=$(shell go env GOARCH)

# Colors for output
COLOR_RESET=\033[0m
COLOR_GREEN=\033[32m
COLOR_BLUE=\033[34m
COLOR_YELLOW=\033[33m

help: ## Display this help screen
	@printf "$(COLOR_BLUE)DNS Benchmark Tool - Available Commands$(COLOR_RESET)\n"
	@printf "\n"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(COLOR_GREEN)%-15s$(COLOR_RESET) %s\n", $$1, $$2}'
	@printf "\n"

build: ## Build the DNS benchmark tool
	@printf "$(COLOR_BLUE)[*] Building $(BINARY_NAME)...$(COLOR_RESET)\n"
	@$(GO) build -ldflags="-w -s" -o $(BINARY_PATH) -v main.go
	@printf "$(COLOR_GREEN)[OK] Build successful: $(BINARY_PATH)$(COLOR_RESET)\n"

run: build ## Build and run the benchmark
	@printf "$(COLOR_BLUE)[*] Running DNS benchmark...$(COLOR_RESET)\n"
	@$(BINARY_PATH)

clean: ## Remove build artifacts
	@printf "$(COLOR_BLUE)[*] Cleaning up...$(COLOR_RESET)\n"
	@rm -f $(BINARY_PATH)
	@printf "$(COLOR_GREEN)[OK] Clean complete$(COLOR_RESET)\n"

deps: ## Download and tidy dependencies
	@printf "$(COLOR_BLUE)[*] Downloading dependencies...$(COLOR_RESET)\n"
	@$(GO) mod download
	@$(GO) mod tidy
	@printf "$(COLOR_GREEN)[OK] Dependencies updated$(COLOR_RESET)\n"

fmt: ## Format code
	@printf "$(COLOR_BLUE)[*] Formatting code...$(COLOR_RESET)\n"
	@$(GO) fmt ./...
	@printf "$(COLOR_GREEN)[OK] Format complete$(COLOR_RESET)\n"

lint: ## Run linter (requires golangci-lint)
	@printf "$(COLOR_BLUE)[*] Running linter...$(COLOR_RESET)\n"
	@which golangci-lint > /dev/null || (printf "$(COLOR_YELLOW)[!] golangci-lint not installed$(COLOR_RESET)\n" && exit 1)
	@golangci-lint run ./...
	@printf "$(COLOR_GREEN)[OK] Lint complete$(COLOR_RESET)\n"

test: ## Run tests
	@printf "$(COLOR_BLUE)[*] Running tests...$(COLOR_RESET)\n"
	@$(GO) test -v ./...
	@printf "$(COLOR_GREEN)[OK] Tests complete$(COLOR_RESET)\n"

cross-compile: ## Build for multiple platforms
	@printf "$(COLOR_BLUE)[*] Cross-compiling...$(COLOR_RESET)\n"
	@mkdir -p dist
	@GOOS=windows GOARCH=amd64 $(GO) build -ldflags="-w -s" -o dist/$(BINARY_NAME)-windows-amd64.exe main.go
	@GOOS=linux GOARCH=amd64 $(GO) build -ldflags="-w -s" -o dist/$(BINARY_NAME)-linux-amd64 main.go
	@GOOS=darwin GOARCH=amd64 $(GO) build -ldflags="-w -s" -o dist/$(BINARY_NAME)-darwin-amd64 main.go
	@GOOS=darwin GOARCH=arm64 $(GO) build -ldflags="-w -s" -o dist/$(BINARY_NAME)-darwin-arm64 main.go
	@printf "$(COLOR_GREEN)[OK] Cross-compile complete in ./dist$(COLOR_RESET)\n"

all: clean deps build ## Clean, download deps, and build

.DEFAULT_GOAL := help

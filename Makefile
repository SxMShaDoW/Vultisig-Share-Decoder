all: cli

cli:
	@echo "Building CLI..."
	@mkdir -p dist
	go build -tags cli -o dist/cli ./cmd/cli

test:
	@echo "Running tests..."
	go test ./...

check:
	@echo "Checking code formatting..."
	go fmt ./...
	@echo "Running go vet..."
	go vet ./...

clean:
	@echo "Cleaning build artifacts..."
	rm -rf dist/

.PHONY: all cli test check clean

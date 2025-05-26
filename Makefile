all: cli webserver wasm

cli:
	@echo "Building CLI..."
	@mkdir -p dist
	go build -tags cli -o dist/cli ./cmd/cli 

webserver:
	@echo "Building web server..."
	@mkdir -p dist
	go build -tags server -o dist/webserver ./cmd/server

wasm:
	@echo "Building WASM..."
	@mkdir -p static
	GOOS=js GOARCH=wasm go build -tags wasm -o static/main.wasm ./cmd/wasm

build: all

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
	rm -f static/main.wasm

.PHONY: all cli webserver wasm build test check clean
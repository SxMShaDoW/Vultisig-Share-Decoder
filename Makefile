all: cli

cli:
	@echo "Building CLI..."
	@mkdir -p dist
	go build -tags cli -ldflags="-s -w" -o dist/cli ./cmd/cli

wasm:
	@echo "Building WASM..."
	@mkdir -p static
	GOOS=js GOARCH=wasm go build -tags wasm -ldflags="-s -w" -o static/main.wasm ./cmd/wasm

pages: wasm
	@echo "Compressing WASM for Pages deployment..."
	gzip -f static/main.wasm
	@echo "Compressed: $$(ls -lh static/main.wasm.gz | awk '{print $$5}')"

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
	rm -f static/main.wasm static/main.wasm.gz

.PHONY: all cli wasm pages test check clean

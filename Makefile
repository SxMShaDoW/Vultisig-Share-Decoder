all: cli

cli:
	@echo "Building CLI..."
	@mkdir -p dist
	go build -ldflags="-s -w" -o dist/cli ./cmd/cli

wasm:
	@echo "Building WASM..."
	@mkdir -p static
	GOOS=js GOARCH=wasm go build -tags wasm -ldflags="-s -w" -o static/main.wasm ./cmd/wasm

derive:
	@echo "Bundling JS address derivation..."
	bun build src/derive.js --outfile static/derive.js --format esm --minify
	@echo "Bundled: $$(ls -lh static/derive.js | awk '{print $$5}')"

pages: wasm derive
	@echo "Compressing WASM for Pages deployment..."
	gzip -f static/main.wasm
	@echo "Compressed: $$(ls -lh static/main.wasm.gz | awk '{print $$5}')"

test:
	@echo "Running Go tests..."
	go test ./...
	@echo "Running JS derive tests..."
	bun run src/derive.test.js

check:
	@echo "Checking code formatting..."
	go fmt ./...
	@echo "Running go vet..."
	go vet ./...

clean:
	@echo "Cleaning build artifacts..."
	rm -rf dist/
	rm -f static/main.wasm static/main.wasm.gz static/derive.js

.PHONY: all cli wasm derive pages test check clean

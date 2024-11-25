.PHONY: wasm cli backend clean all

# Default target
all: wasm cli backend

# Build WASM version
wasm:
	GOOS=js GOARCH=wasm go build -tags wasm -o static/main.wasm $$(ls *.go | grep -v '_cli.go\|_backend.go')

# Build CLI version
cli:
	mkdir -p cli
	go build -tags cli -o cli/cli-recover $$(ls *.go | grep -v 'wasm.go\|_backend.go')

# Build and run backend
backend:
	go build -tags server -o webserver ./main_backend.go
	chmod +x webserver

# Clean built files
clean:
	rm -f static/main.wasm cli/cli-recover webserver
.PHONY: all cli wasm server clean

all: cli wasm server

cli:
	go build -tags cli -o dist/cli ./cmd/cli 

wasm:
	GOOS=js GOARCH=wasm go build -tags wasm -o static/main.wasm ./cmd/wasm

server:
	go build -tags server -o dist/webserver ./cmd/server

clean:
	rm -f dist/* static/main.wasm
.PHONY: build build-linux-amd64 build-linux-arm64 build-all clean

# Build for current platform (requires embedded/slipnet to be placed manually)
build:
	go build -o bin/dns-multiplexer

# Build for Linux amd64 with bundled slipnet
build-linux-amd64:
	cp bin/slipnet-linux-amd64 embedded/slipnet
	GOOS=linux GOARCH=amd64 go build -o bin/dns-multiplexer-linux-amd64
	rm -f embedded/slipnet

# Build for Linux arm64 with bundled slipnet
build-linux-arm64:
	cp bin/slipnet-linux-arm64 embedded/slipnet
	GOOS=linux GOARCH=arm64 go build -o bin/dns-multiplexer-linux-arm64
	rm -f embedded/slipnet

# Build both Linux targets
build-all: build-linux-amd64 build-linux-arm64

clean:
	rm -f embedded/slipnet
	rm -f bin/dns-multiplexer bin/dns-multiplexer-linux-amd64 bin/dns-multiplexer-linux-arm64

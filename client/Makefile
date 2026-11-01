# Build flags to hide Windows CMD console window: -ldflags="-H=windowsgui"
.PHONY: build build-windows

build:
	go build -o linnas-client .

build-windows:
	GOOS=windows GOARCH=amd64 go build -ldflags="-H=windowsgui -s -w" -o linnas-client.exe .

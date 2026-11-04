# Makefile for LinNAS Local Cloud Client (Wails v2)
.PHONY: build build-linux build-windows test clean

build: build-linux

build-linux:
	wails build -tags webkit2_41 -o linnas-client

build-windows:
	wails build -platform windows/amd64 -windowsconsole=false -o linnas-client.exe

test:
	go test -v ./...

clean:
	rm -rf build/bin

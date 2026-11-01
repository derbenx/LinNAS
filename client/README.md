# LinNAS Local Cloud Client

Cross-platform desktop system tray client for LinNAS Local Cloud.

## Building for Windows (No CMD Console Window)
To build the Windows executable without a CMD console window popping up:
```bash
go build -ldflags="-H=windowsgui -s -w" -o linnas-client.exe .
```

## Building for Linux
```bash
go build -o linnas-client .
```

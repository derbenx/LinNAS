# LinNAS Local Cloud Client

Cross-platform desktop client for LinNAS Local Cloud built with [Wails v2](https://wails.io).

## Features
- **Wails v2 Desktop Architecture:** Native webview with zero frontend framework overhead (vanilla HTML/CSS/JS matching LinNAS theme).
- **Auto-Reconnection & Desynchronization Recovery:** Automatic connection recovery with staged backoffs (1-2 mins, 5 mins after 30 mins, 15 mins after 1 hr) and session re-authentication.
- **Combined SMART Diagnostics:** Unified tab ordering Server Storage Drives, Local PC Storage Drives, and Remote Client devices grouped by IP.
- **Fullscreen App Detection:** Defers critical drive failure popups until after the user exits any active fullscreen game/app.
- **Run on Startup Support:** System startup toggle for Windows (Run registry key) and Linux (XDG autostart `.desktop`).

## Building for Linux
```bash
make build-linux
```

## Building for Windows
```bash
make build-windows
```

## Running Tests
```bash
make test
```

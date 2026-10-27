# Debian Server Manager

A lightweight, high-performance web-based server management control panel for **Debian Linux** written in Golang, listening on port **8080**.

Featuring a modular, decoupled plugin architecture, **Debian Server Manager** enables users to configure network interfaces, manage Samba shares and users, mount physical partitions/ISOs/VHDs/VeraCrypt containers, convert adblock lists into `dnsmasq` rules, edit system configuration files, monitor SMART drive health and system telemetry, and manage server power options—all through a clean, router-style dark interface.

---

## 🌟 Key Features

- **Golang Core Web Server**: Runs on port `8080` with minimal memory footprint and zero external binary dependencies.
- **Decoupled HTML/JS Plugin Architecture**: Each plugin resides in its own `html/<plugin-id>/` directory containing an `index.htm` interface and a `plugin.json` command manifest. Users can easily add custom plugins without recompiling the Go application!
- **Pre-Login Read-Only Public Status Dashboard**: Displays CPU cores, free RAM, uptime, load averages, swap memory, disk space, and SMART drive health prior to logging in, complete with a bright green **LOGIN TO MANAGE SERVER** button at the top header.
- **Privilege Separation & Security**:
  - Distinguishes standard commands (`_cmd`) from privileged operations (`_sudo`).
  - Strict parameter regex validation (`safeVarReg`) prevents shell metacharacter command injection (`$`, `;`, `|`, `&`, `` ` ``, `<`, `>`, quotes, newlines).
  - Session cookie authentication with SHA-256 password hash storage persisted to `linnas.data`.
- **Minimal Debian Netinstall Compatibility**: Automatically detects missing packages (e.g., `dnsmasq`, `smartmontools`, `tcplay`, `iputils-ping`, `traceroute`) common on netinstall minimal builds, providing one-click APT installation banners inside plugin views.
- **Systemd Boot Service Autostart**: Enable or disable application autostart on server bootup directly from the web interface.

---

## 📦 Plugin Modules Included

### 1. 🖥️ Server Status & Power Management (`status`)
- **Conky-Style Telemetry**: CPU cores/model, free RAM, load averages (1m, 5m, 15m), swap memory, server uptime, and active network interface IP addresses.
- **Disk Space Available**: Parses `df -h` storage mounts and usage percentages.
- **SMART Drive Health Monitor**: Queries `smartctl -H` health status and detailed SMART diagnostic attributes for SATA/NVMe drives.
- **System Services Status**: Monitor, start, stop, and restart core services (`smbd`, `dnsmasq`, `apache2`, `mysql`, `ssh`).
- **Power Operations & Scheduling**: Instant Power Off, Reboot, and scheduled shutdown/reboot timers (e.g., in +30 minutes) with task cancellation.
- **Systemd Boot Autostart**: One-click enable/disable automatic application startup on system bootup.

### 2. 📦 APT Package Manager & Module Installer (`apt`)
- Scans installed vs uninstalled plugins using `check_cmd` or `dpkg-query`.
- Install or remove software packages and plugin modules.
- **Sticky Console Drawer**: Live progress spinner and terminal output drawer at the bottom of the screen.
- **Dynamic Sidebar Refresh**: Automatically reloads sidebar navigation via `postMessage` upon installing or removing plugins without refreshing the browser.

### 3. 📁 SMB Shares & User Credentials Config (`smb`)
- **Samba User Management**: Create, update, or delete multiple Samba users (`smbpasswd` / `pdbedit`).
- **Share Configuration**: Define share names, directory paths with folder browser modals, read-only toggles, and share active/disabled switches.
- **Access Control Permissions**: Restrict shares to specific Samba users (`valid users`) or allow guest public access.
- **System Config Sync**: Syncs share configurations to `/etc/samba/conf.d/shares.conf` and ensures inclusion in `/etc/samba/smb.conf`.

### 4. 💾 Local Drives, ISO & VHD Mount Manager (`drive_mount`)
- **Physical Partition Scanning**: Parses block devices and partition hierarchies (`lsblk -J`), showing device names, filesystem types, volume labels, sizes, and UUIDs.
- **`/etc/fstab` Boot Persistence**: Checkbox option to auto-mount drives on server bootup via UUID in `/etc/fstab`.
- **Virtual Disk Image Mounting**: Mount ISO optical images (`.iso`) and VHD virtual disk containers (`.vhd`, `.vhdx`, `.img`, `.raw`) via loop devices.
- **SMB Auto-Export**: Option to automatically publish mounted folders as active Samba network shares.
- **File/Folder Browser Modal**: Interactive folder picker with `+ Create Folder` capability.

### 5. 🔒 VeraCrypt / TrueCrypt Container Config (`veracrypt`)
- **`tcplay` Integration**: Mount and dismount encrypted VeraCrypt (`.hc`) and TrueCrypt (`.tc`) container files on Debian using native `tcplay`.
- **File & Folder Selection Modals**: File picker for container files and folder browser for mount points with auto-suggested `/mnt/[vcfilename]` paths.
- **SMB Share Integration**: Option to export mounted encrypted volumes over Samba.

### 6. 🛡️ DNS Forwarder & AdBlock Manager (`dns`)
- **Upstream Forwarders**: Configure primary (e.g., `1.1.1.1`) and secondary (e.g., `8.8.8.8`) DNS resolvers.
- **Multi-Format AdBlock Converter**: Paste Hosts files (`0.0.0.0 domain`), AdBlock syntax (`||domain^`), or raw domain lists to automatically convert them into `dnsmasq` blocking rules (`address=/domain/0.0.0.0`).
- **System Config Sync**: Syncs rules directly to `/etc/dnsmasq.d/99-server-manager-dns.conf`.

### 7. 🌐 DHCP Server Config (`dhcp`)
- **IP Allocation Pools**: Configure network interface, subnet netmask, start/end IP allocation ranges, default router gateway, and lease duration.
- **Service Status Monitoring**: Checks `dnsmasq` service status, reports running/stopped state, and displays error logs if inactive.
- **System Config Sync**: Writes settings to `/etc/dnsmasq.d/99-server-manager-dhcp.conf`.

### 8. 🔌 LAN Network Settings (`lan`)
- **Interface Auto-Detection**: Detects active wired Ethernet interfaces (`ip -j link`).
- **IP Addressing Modes**: Switch between `Automatic (DHCP)` and `Manual (Static IP)` with CIDR prefix masks.
- **DHCP Lease Renewal**: One-click DHCP lease release/renewal.
- **DNS Overrides**: Set custom primary and secondary DNS resolvers in `/etc/resolv.conf`.
- **Hardware Warning Banner**: Displays driver installation tips if Ethernet hardware is absent.

### 9. 📶 Wi-Fi Wireless Config (`wifi`)
- **AP Scanning**: Scan nearby wireless Access Points (`iwlist scan`), showing SSID, signal strength %, channel, and security encryption mode.
- **Connection Setup**: Connect to Wi-Fi networks using `nmcli` or `wpa_supplicant`.
- **Secure Storage**: WiFi passwords stored in base64 format in `data.json`.
- **Hardware Warning Banner**: Displays adapter troubleshooting steps if wireless hardware is missing.

### 10. 📝 System Configuration File Editor (`editor`)
- **Quick Preset Shortcuts**: One-click opening for `/etc/fstab`, `/etc/samba/smb.conf`, `/etc/dnsmasq.conf`, `/etc/network/interfaces`, and `/etc/hosts`.
- **File Size Safety Limits**: Inspects file size prior to loading and enforces a **2 MB maximum size limit** to prevent browser memory freezes on large log or binary files.
- **Admin / Root Privilege Warning Banner**: Displays a prominent warning when editing system configuration files in elevated mode.
- **Raw File Writing**: Saves file changes safely using direct HTTP payloads (`/api/file/write`).

### 11. 📡 Network Diagnostics (`ping`)
- Execute ICMP `ping` latency tests with configurable packet counts.
- Execute `traceroute` route hop tracking with configurable max hop limits.
- Quick preset buttons for Cloudflare (`1.1.1.1`) and Google DNS (`8.8.8.8`).
- One-click APT installer for missing `iputils-ping` and `traceroute` netinstall packages.

### 12. 🐚 Neofetch System Information (`neofetch`)
- Display Debian OS summary, kernel release, uptime, shell, memory usage, and ASCII distribution logo.

### 13. 🌐 Apache Web Server (`apache`)
- Configure listening HTTP ports, document root paths (`/var/www/html`), server admin email, and directory indexes.

### 14. 🗄️ MySQL / MariaDB Config (`mysql`)
- Manage database listening port, create new database users (`CREATE USER`), grant privileges, and launch SQL web clients (e.g. phpMyAdmin).

### 15. 🐘 PHP Scripting Engine (`php`)
- Install PHP runtime versions, FPM services, switch CLI alternatives (`update-alternatives`), and adjust `php.ini` directives (`memory_limit`, `upload_max_filesize`).

---

## 🚀 Getting Started

### Prerequisites
- **Debian Linux** (Debian 11 / 12, standard or netinstall)
- **Go 1.18+** (for building from source)

### Installation & Execution

1. Clone or download the repository to your Debian server:
   ```bash
   git clone https://github.com/your-user/debian-server-manager.git
   cd debian-server-manager
   ```

2. Run the application:
   ```bash
   go run main.go
   ```
   *or compile a binary:*
   ```bash
   go build -o server-manager main.go
   ./server-manager
   ```

3. Open your web browser and navigate to:
   ```
   http://<your-server-ip>:8080
   ```

4. **Authentication**:
   - **Default Username**: `admin`
   - **Default Password**: `adminpassword`
   - *Note*: Unauthenticated users can view read-only Server Status telemetry. Click the bright green **LOGIN TO MANAGE SERVER** button or the **🔑 Pass** button in the sidebar to change your account password (saved as a SHA-256 hash in `linnas.data`).

---

## 🛠️ Configuration & Storage Files

- `config.json`: Server port and authentication settings.
- `linnas.data`: Stores custom user account credentials and SHA-256 password hash.
- `html/<plugin-id>/data.json`: Persisted JSON settings for individual plugins.
- `/etc/samba/conf.d/shares.conf`: Synchronized Samba network share definitions.
- `/etc/dnsmasq.d/99-server-manager-dns.conf`: Synchronized DNS forwarding and adblock rules.
- `/etc/dnsmasq.d/99-server-manager-dhcp.conf`: Synchronized DHCP pool allocation rules.
- `/etc/fstab`: Managed UUID partition boot entries.

---

## 🛡️ License

Distributed under the MIT License.

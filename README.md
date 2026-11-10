# LinNAS v1.0

A lightweight, high-performance web-based server management control panel for **Debian Linux** written in Golang, listening on port **8080**.

Featuring a modular, decoupled plugin architecture, **LinNAS** enables users to manage files, media, 3D models, Samba network shares, local drives, ISO/VHD/VeraCrypt mounts, network interfaces, firewall rules, and system telemetry—all through a clean, router-style dark interface.

---

## 🌟 Key Features

- **Golang Core Web Server**: Runs on port `8080` with minimal memory footprint and zero external binary dependencies.
- **Decoupled HTML/JS Plugin Architecture**: Each plugin resides in its own `html/<plugin-id>/` directory containing an `index.htm` interface, a `plugin.json` command manifest, and a `plugin.info` help file.
- **Dynamic Help & Documentation (`LinNAS v1.0`)**: Searchable, collapsible documentation under **SYSTEM -> Help**, along with per-plugin `ℹ️ Info` help modals inside every plugin header.
- **Tools Suite**: Includes File Manager, File Editor, Image Viewer, Video Player (HTTP 206 Range streaming), Audio Player (with continuous background playback bar), and 3D Model Viewer (Three.js STL/OBJ/GLTF renderer).
- **Pre-Login Read-Only Public Status Dashboard**: Displays CPU cores, free RAM, uptime, load averages, swap memory, and network IP addresses prior to logging in, complete with a bright green **LOGIN TO MANAGE SERVER** button.
- **Privilege Separation & Security**:
  - Distinguishes standard commands (`_cmd`) from privileged operations (`_sudo`).
  - Strict parameter regex validation (`safeVarReg`) prevents shell metacharacter command injection (`$`, `;`, `|`, `&`, `` ` ``, `<`, `>`, quotes, newlines).
  - Session cookie authentication with SHA-256 password hash storage persisted to `linnas.data`.
- **Systemd Boot Service Autostart**: Enable or disable application autostart on server bootup directly from the web interface, complete with autostart issue diagnostic logging.

---

## 📦 Plugin Modules Included

### SYSTEM
- **🖥️ Server Status & Power (`status`)**: CPU, RAM, uptime, load averages, swap, system services, and power off / reboot scheduling.
- **📦 APT Package Manager (`apt`)**: Install/remove software packages with live streaming execution output.
- **⚙️ Server Settings (`settings`)**: Hostname, HTTP port, feature toggles, admin password, and systemd boot autostart.
- **❓ Help & Docs (`help`)**: LinNAS v1.0 documentation with search filter and collapsible category sections.

### TOOLS
- **📂 File Manager (`filemanager`)**: Directory navigation, create folder, cut, copy, paste, rename, bulk delete, drag-and-drop file upload, and PDF new-tab viewing.
- **📝 File Editor (`editor`)**: System configuration file editor with quick presets, file size safety checks, and root warning badges.
- **🖼️ Image Viewer (`imageviewer`)**: Image gallery with zoom, panning, keyboard arrow navigation, and F11 native browser fullscreen mode.
- **🎬 Video Player (`videoplayer`)**: HTML5 video player with HTTP Range request seeking (HTTP 206), F11 fullscreen, volume/mute shortcuts, 5s/15s seeks, and frame-by-frame stepping (`,` and `.`).
- **🎵 Audio Player (`audioplayer`)**: Stream MP3, WAV, OGG, FLAC, and AAC tracks with folder playlist scanning and persistent background playback across plugin navigation.
- **🧊 3D Model Viewer (`modelviewer`)**: Render STL, OBJ, GLTF, GLB, and 3MF 3D models using Three.js with orbit camera controls and wireframe mode.

### NETWORK
- **🔌 LAN Network Config (`lan`)**: Ethernet interface addressing, static IP / CIDR, DNS resolvers, and independent DHCP/Manual modes.
- **📶 Wi-Fi Config (`wifi`)**: Wireless AP scanner and wpa_supplicant / nmcli connection manager.
- **🛡️ DNS & AdBlock (`dns`)**: Upstream forwarders and multi-format adblock list conversion into `dnsmasq` blocking rules.
- **🌐 DHCP Server (`dhcp`)**: Manage `dnsmasq` DHCP IP allocation pools and lease times.
- **📡 Network Diagnostics (`ping`)**: Execute ICMP `ping` and `traceroute` route hop tests.
- **🛡️ UFW Firewall (`ufw`)**: Manage UFW rules, open/close TCP/UDP ports, and service presets.

### STORAGE
- **📁 SMB Shares & Credentials (`smb`)**: Manage Samba shares, user permissions (`pdbedit`), share import, and home directory visibility toggles (`[homes]`).
- **💾 Local Drives, ISO & VHD (`drive_mount`)**: Mount physical partitions, read-only ISOs, and VHD images with optional SMB user restricted auto-sharing.
- **☁️ Local Cloud Server (`cloud`)**: Private multi-client file synchronization server with per-folder `.cloud_data` ledgers, clock skew compensation, opt-out selective folder sync, versioned/shared `RecycleBin`, transfer throttling, and Special Root Folder protection policies.
- **📻 DLNA Server & Caster (`dlna`)**: DLNA 1.5 & UPnP AV media server with dual backends (built-in pure Go engine and MiniDLNA) supporting legacy puck streamers like AudioCast M5, folder selection, and direct casting from the Audio Player.
- **🔒 VeraCrypt Container Manager (`veracrypt`)**: Mount encrypted VeraCrypt (`.hc`) and TrueCrypt (`.tc`) volumes using `tcplay`.

---

## ☁️ Local Cloud & Desktop Client App

LinNAS includes an end-to-end encrypted private cloud service paired with a lightweight, cross-platform desktop client application (`client/` built in Go and Wails v2):

- **Master Server & Multi-Client Architecture**:
  - The LinNAS server serves as the master storage repository.
  - Both server and connected clients maintain independent, unshared `.cloud_data` ledgers inside each folder to track active files, deleted tombstones, and modification histories (capped at 10 entries per file).
  - The client automatically compares client-server clock offset upon connection and normalizes timestamps to ensure the newest version is always preserved regardless of machine clock skew.
- **Opt-Out Selective Sync**:
  - In the client app, folders default to enabled (checked) so newly created directories are automatically synchronized.
  - Users can opt out of any folder by unchecking it. Unchecking a folder cleanly erases the folder from the client's local PC while keeping the files safe on the server for other clients.
  - Re-checking an unchecked folder instantly downloads the folder and its contents back from the server.
- **Shared RecycleBin & Versioning**:
  - The `RecycleBin/` folder is shared and synchronized across clients.
  - When files or folders are deleted or overwritten by a client, the server archives timestamped copies into `RecycleBin/` with companion `.restore_info.json` origin metadata for easy recovery.
  - Deleting files directly from inside `RecycleBin/` permanently deletes them without re-recycling.
  - The root `RecycleBin/` folder itself is protected from deletion.
- **Bandwidth Throttling**:
  - User-configurable transfer speed limiter (Unlimited, 250 KB/s, 500 KB/s, 1 MB/s, 2.5 MB/s, 5 MB/s) in the desktop client.
- **Special Root Folders**:
  - Configure folder protection rules in the Server Local Cloud interface:
    - **Add only**: Allows clients to add new files and subdirectories with unique names. Attempting to overwrite existing files or delete files/folders is disallowed.
    - **Read only**: Disallows all additions, modifications, and deletions.
  - When a client detects local changes in protected folders:
    - In **Read-Only** folders, the client offers to **Move** the files to another location or **Dismiss** (ignoring the file in `.cloud_data` so sync continues smoothly).
    - In **Add-Only** collision conflicts, the client offers to **Move file**, **Rename file**, or **Rename with prefix** before uploading.

---

## 🚀 Getting Started

### Installation & Execution

1. Clone or download the repository to your Debian server:
   ```bash
   git clone https://github.com/your-user/linnas.git
   cd linnas
   ```

2. Run the application:
   ```bash
   go run main.go
   ```
   *or build executable:*
   ```bash
   go build -o linnas main.go
   ./linnas
   ```

3. Open your web browser and navigate to:
   ```
   http://<your-server-ip>:8080
   ```

4. **Authentication**:
   - **Default Username**: `admin`
   - **Default Password**: `adminpassword`
   - **Security Recommendation**: Change default credentials under **Server Settings** -> **Admin Account Password**.

---

## 🛠️ Configuration & Storage Files

- `config.json`: Server port and default settings.
- `linnas.data`: Stores custom user account credentials and SHA-256 password hash.
- `html/<plugin-id>/plugin.info`: Plugin help documentation file.
- `html/<plugin-id>/data.json`: Persisted JSON settings for individual plugins.
- `/etc/samba/conf.d/shares.conf`: Synchronized Samba network share definitions.

---

## 🛡️ License

Distributed under the MIT License.

# LinNAS v1.0 - expect bugs ;)

A lightweight, high-performance web-based server management control panel for **Debian Linux** written in Golang.
Typically used with a Debian net install ISO, bare minimum install, just SSH server and standard utilities. You can use it in a GUI based server too, but GUI and remote access is redundant with LinNAS.

LinNAS is less than 15mb whereas a whole GUI install which can run into Gigs. To use it as a light OS GUI, basically you set up your spare pc to boot into LinNAS on startup and configure it on the network. Then you login in to the LinNAS PC via your regular PC's browser on port 8080, similar to how you access your router, using whatever IP was setup or DHCP assigned. ex; http://192.168.1.10:8080 

From there you have a modular, decoupled plugin architecture, that enables you to manage files, media, 3D models, Samba network shares, local drives, ISO/VHD/VeraCrypt mounts, network interfaces, firewall rules, and system telemetry—all through a clean, router-style dark interface. There is also a 'Virtual Desktop' plugin included where it can make it look like a whole desktop GUI you remote in to, press f11 to go full screen for the full effect. The virtual desktop lets you open file browser windows to access your files, play audio, video, open 3D files.. etc.

---

Packages:<br>
<img width="960" height="540" alt="linnas-packages" src="https://github.com/user-attachments/assets/6739eafa-181a-49fb-975a-62b7aba3c11c" />

Drives:<br>
<img width="960" height="540" alt="linnas-drives" src="https://github.com/user-attachments/assets/d31d7f1a-6427-407f-8b99-38150b0c830c" />

Virtual desktop:<br>
<img width="960" height="540" alt="linnas-vdesktop" src="https://github.com/user-attachments/assets/1784a73c-3c94-41f2-92c9-ff2c68002463" />

File manager:<br>
<img width="960" height="540" alt="linnas-fm" src="https://github.com/user-attachments/assets/3f8ae981-9c37-4cd1-acf2-42d8be8e3b4d" />

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
- **🔒 VeraCrypt Container Manager (`veracrypt`)**: Mount encrypted VeraCrypt (`.hc`) and TrueCrypt (`.tc`) volumes using `tcplay`.

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

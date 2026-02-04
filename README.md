# Windows Security Tools - PowerShell Installation Guide

## 📋 Table of Contents
- [Overview](#overview)
- [System Requirements](#system-requirements)
- [Pre-Installation Checklist](#pre-installation-checklist)
- [Installation Instructions](#installation-instructions)
- [What Gets Installed](#what-gets-installed)
- [Installation Locations](#installation-locations)
- [Post-Installation Steps](#post-installation-steps)
- [Tool Usage Examples](#tool-usage-examples)
- [Troubleshooting](#troubleshooting)
- [Complete Tool List](#complete-tool-list)
- [Updating Tools](#updating-tools)
- [Uninstallation](#uninstallation)
- [Security Considerations](#security-considerations)
- [FAQ](#faq)

---

## 🎯 Overview

Automated PowerShell script that installs 60+ Windows-native security tools for bug bounty hunting, penetration testing, and application security research.

### Features
- ✅ **Windows-Specific Tools**: Sysinternals, Process Hacker, x64dbg, dnSpy, ILSpy
- ✅ **Cross-Platform Tools**: Burp Suite, OWASP ZAP, Ghidra, Android tools
- ✅ **Go Security Tools**: Nuclei, Subfinder, Httpx, Ffuf, Gobuster (24 tools)
- ✅ **Python Security Tools**: Impacket, CrackMapExec, Arjun, XSStrike (19 tools)
- ✅ **Android Tools**: ADB, Android Studio, JADX, APKTool, scrcpy, MobSF
- ✅ **Wordlists**: SecLists, PayloadsAllTheThings
- ✅ **Automatic PATH Configuration**: All tools accessible from command line
- ✅ **Comprehensive Logging**: Track installation progress and errors

---

## 💻 System Requirements

| Requirement | Minimum | Recommended |
|------------|---------|-------------|
| **OS** | Windows 10 (64-bit) | Windows 11 (64-bit) |
| **PowerShell** | 5.1 | 7.x |
| **RAM** | 8GB | 16GB |
| **Disk Space** | 20GB free | 50GB free |
| **Internet** | Stable connection | High-speed connection |
| **Admin Rights** | Required | Required |

### Software Prerequisites
- Windows 10/11 with latest updates
- PowerShell 5.1 or higher
- .NET Framework 4.8 or higher
- Administrator privileges
- Active internet connection

---

## ✅ Pre-Installation Checklist

Complete these steps before running the installation script:

### 1. System Preparation
- [ ] **Backup your data** - Always backup important files before major installations
- [ ] **Check disk space** - Ensure at least 20GB free space on C: drive
- [ ] **Update Windows** - Install all pending Windows updates
- [ ] **Close applications** - Close all running applications to avoid conflicts

### 2. Security Software
- [ ] **Temporarily disable antivirus** - Many security tools will be flagged as malicious
  - Right-click antivirus icon in system tray
  - Select "Disable protection" or "Pause protection"
  - Set duration to 1-2 hours
- [ ] **Add exclusions** (if not disabling):
  - `C:\Users\YourUsername\security-tools\`
  - `C:\Users\YourUsername\go\bin\`
  - `C:\ProgramData\chocolatey\`

### 3. Network Configuration
- [ ] **Stable internet connection** - Installation downloads several gigabytes
- [ ] **Disable VPN temporarily** - VPNs can cause download timeouts
- [ ] **Check proxy settings** - Ensure proxy isn't blocking downloads

### 4. PowerShell Setup
- [ ] **Test PowerShell version**:
  ```powershell
  $PSVersionTable.PSVersion
  # Should show 5.1 or higher
  ```

---

## 🚀 Installation Instructions

### Method 1: Standard Installation (Recommended)

#### Step 1: Download the Script
Save `Install-WindowsSecurityTools.ps1` to your Downloads folder.

#### Step 2: Open PowerShell as Administrator
1. Press `Windows + X` on your keyboard
2. Select **"Windows PowerShell (Admin)"** or **"Terminal (Admin)"**
3. Click **"Yes"** on the User Account Control (UAC) prompt

#### Step 3: Navigate to Script Location
```powershell
cd $env:USERPROFILE\Downloads
```

#### Step 4: Set Execution Policy
```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
```

**What this does**: Allows the script to run for this session only. Your system policy remains unchanged after closing PowerShell.

#### Step 5: Run the Installation Script
```powershell
.\Install-WindowsSecurityTools.ps1
```

#### Step 6: Monitor Installation
- Watch the colored output for progress
- Installation takes 40-70 minutes depending on internet speed
- Do not close PowerShell window during installation
- Script will show summary at the end

---

### Method 2: Quick Installation (One-Liner)

After downloading the script to Downloads folder:

```powershell
cd $env:USERPROFILE\Downloads; Set-ExecutionPolicy Bypass -Scope Process -Force; .\Install-WindowsSecurityTools.ps1
```

---

### Method 3: Run from Any Location

If the script is in a different location:

```powershell
# Example: Script on Desktop
cd $env:USERPROFILE\Desktop
Set-ExecutionPolicy Bypass -Scope Process -Force
.\Install-WindowsSecurityTools.ps1

# Example: Script on D: drive
cd D:\Scripts
Set-ExecutionPolicy Bypass -Scope Process -Force
.\Install-WindowsSecurityTools.ps1
```

---

## 📦 What Gets Installed

### Installation Timeline

```
Phase 1: System Dependencies        [▓▓▓▓░░░░░░] 5-10 min
Phase 2: Windows-Specific Tools     [▓▓░░░░░░░░] 2-5 min
Phase 3: Python Security Tools      [▓▓▓▓░░░░░░] 5-10 min
Phase 4: Go Security Tools          [▓▓▓▓▓▓░░░░] 10-15 min
Phase 5: Web Application Security   [▓▓▓▓░░░░░░] 5-10 min
Phase 6: Android Security Tools     [▓▓▓▓░░░░░░] 5-10 min
Phase 7: Reverse Engineering Tools  [▓▓▓▓░░░░░░] 5-10 min
Phase 8: Wordlists                  [▓▓░░░░░░░░] 2-5 min
Phase 9: Configuration & Updates    [▓░░░░░░░░░] 1-2 min
                                    ─────────────────────
                          Total Time: 40-70 minutes
```

### Detailed Installation Phases

#### Phase 1: System Dependencies (5-10 minutes)
```
Installing:
  → Chocolatey Package Manager
  → Git 2.43+
  → Python 3.11+
  → Go 1.21+
  → Node.js 20+
  → Visual Studio Code
  → 7-Zip
  → wget, curl, jq
  → Docker Desktop
  → VirtualBox
  → Wireshark
  → Nmap
  → Windows Terminal
  → .NET SDK
  → Visual Studio Build Tools
```

#### Phase 2: Windows-Specific Tools (2-5 minutes)
```
Installing:
  → Sysinternals Suite
    • Process Monitor (procmon.exe)
    • Process Explorer (procexp.exe)
    • Autoruns (autoruns.exe)
    • TCPView (tcpview.exe)
    • PsExec, PsTools
  → Process Hacker 2
  → x64dbg (Windows debugger)
  → dnSpy (.NET decompiler/debugger)
  → ILSpy (.NET decompiler)
  → Detect It Easy (PE file analyzer)
```

#### Phase 3: Python Security Tools (5-10 minutes)
```
Installing:
  → impacket (Windows exploitation toolkit)
  → crackmapexec (Active Directory pentesting)
  → bloodhound (AD attack paths)
  → mitm6 (IPv6 attacks)
  → responder (LLMNR/NBT-NS poisoner)
  → pywerview (PowerView Python)
  → ldapdomaindump (AD enumeration)
  → kerbrute (Kerberos attacks)
  → arjun (parameter discovery)
  → xsstrike (XSS scanner)
  → sublist3r (subdomain enumeration)
  → requests, beautifulsoup4
  → selenium, playwright
  → shodan, censys (API clients)
```

#### Phase 4: Go Security Tools (10-15 minutes)
```
Installing ProjectDiscovery Suite:
  → nuclei (vulnerability scanner)
  → subfinder (subdomain enumeration)
  → httpx (HTTP probe)
  → katana (web crawler)
  → naabu (port scanner)
  → dnsx (DNS toolkit)
  → interactsh (OOB testing)
  → notify (notification system)

Installing Fuzzing Tools:
  → ffuf (web fuzzer)
  → gobuster (directory/DNS brute-forcer)

Installing Discovery Tools:
  → amass (subdomain enumeration)
  → assetfinder (subdomain finder)
  → gau (URL discovery)
  → waybackurls (Wayback Machine URLs)
  → hakrawler (web crawler)
  → gospider (web spider)

Installing Utility Tools:
  → gf (pattern matching)
  → anew (unique lines)
  → unfurl (URL parser)
  → qsreplace (query string replacer)

Installing Security Tools:
  → dalfox (XSS scanner)
  → kxss (XSS parameter finder)
  → crlfuzz (CRLF injection scanner)
  → gitleaks (secret scanner)
  → trufflehog (credential scanner)
```

#### Phase 5: Web Application Security (5-10 minutes)
```
Installing:
  → Burp Suite Community Edition
    (Downloaded to security-tools folder - manual install required)
  → OWASP ZAP (automated install)
```

#### Phase 6: Android Security Tools (5-10 minutes)
```
Installing:
  → Android SDK Platform Tools
    • ADB (Android Debug Bridge)
    • Fastboot
  → Android Studio (full IDE)
  → JADX (APK decompiler)
  → APKTool (APK reverse engineering)
  → scrcpy (screen mirroring tool)
  → MobSF (Mobile Security Framework - Docker image)
```

#### Phase 7: Reverse Engineering Tools (5-10 minutes)
```
Installing:
  → Ghidra (NSA reverse engineering tool)
  → IDA Free (download link provided for manual install)
```

#### Phase 8: Wordlists (2-5 minutes)
```
Cloning:
  → SecLists (40,000+ wordlists)
    • Passwords
    • Usernames
    • Web content discovery
    • Fuzzing payloads
  → PayloadsAllTheThings (exploit payloads)
    • XSS payloads
    • SQL injection
    • Command injection
    • File upload bypasses
```

#### Phase 9: Configuration & Updates (1-2 minutes)
```
Configuring:
  → Update Nuclei templates (3000+ templates)
  → Add tools to PATH environment variable
  → Create directory structure
  → Generate installation log
  → Display summary report
```

---

## 📁 Installation Locations

### Main Installation Directory
```
C:\Users\YourUsername\security-tools\
│
├── platform-tools\              # Android SDK Platform Tools
│   ├── adb.exe                  # Android Debug Bridge
│   ├── fastboot.exe             # Fastboot utility
│   ├── dmtracedump.exe
│   ├── etc1tool.exe
│   ├── hprof-conv.exe
│   ├── lib\
│   ├── make_f2fs.exe
│   └── mke2fs.exe
│
├── jadx\                        # JADX APK Decompiler
│   ├── bin\
│   │   ├── jadx.bat
│   │   └── jadx-gui.bat
│   ├── lib\
│   └── jadx-*.jar
│
├── apktool\                     # APKTool
│   ├── apktool.jar
│   └── apktool.bat
│
├── ghidra\                      # Ghidra Reverse Engineering
│   ├── ghidra_10.x_PUBLIC\
│   │   ├── ghidraRun.bat
│   │   ├── support\
│   │   ├── Ghidra\
│   │   └── docs\
│   └── ghidra.zip
│
├── dnspy\                       # dnSpy .NET Decompiler
│   ├── dnSpy.exe
│   ├── dnSpy-x86.exe
│   └── [various DLLs]
│
├── detect-it-easy\              # Detect It Easy PE Analyzer
│   ├── die.exe
│   ├── diec.exe
│   └── db\
│
├── wordlists\                   # Security Wordlists
│   ├── SecLists\
│   │   ├── Discovery\
│   │   │   ├── Web-Content\
│   │   │   ├── DNS\
│   │   │   └── Infrastructure\
│   │   ├── Fuzzing\
│   │   ├── Passwords\
│   │   ├── Usernames\
│   │   └── Payloads\
│   └── PayloadsAllTheThings\
│       ├── XSS Injection\
│       ├── SQL Injection\
│       ├── Command Injection\
│       └── File Upload\
│
├── tools\                       # Additional tools directory
├── scripts\                     # Custom scripts directory
├── results\                     # Scan results directory
├── configs\                     # Configuration files directory
└── burpsuite_community_windows-x64.exe  # Burp Suite installer
```

### Go Tools Location
```
C:\Users\YourUsername\go\
│
├── bin\                         # Go binaries (in PATH)
│   ├── nuclei.exe
│   ├── subfinder.exe
│   ├── httpx.exe
│   ├── katana.exe
│   ├── naabu.exe
│   ├── dnsx.exe
│   ├── interactsh-client.exe
│   ├── notify.exe
│   ├── ffuf.exe
│   ├── gobuster.exe
│   ├── amass.exe
│   ├── assetfinder.exe
│   ├── gau.exe
│   ├── waybackurls.exe
│   ├── hakrawler.exe
│   ├── gospider.exe
│   ├── gf.exe
│   ├── anew.exe
│   ├── unfurl.exe
│   ├── qsreplace.exe
│   ├── dalfox.exe
│   ├── kxss.exe
│   ├── crlfuzz.exe
│   ├── gitleaks.exe
│   └── trufflehog.exe
│
├── pkg\                         # Go packages (cache)
└── src\                         # Go source code (optional)
```

### System Tools (via Chocolatey)
```
C:\ProgramData\chocolatey\
│
├── bin\                         # Chocolatey binaries (in PATH)
│   ├── git.exe
│   ├── python.exe
│   ├── go.exe
│   ├── node.exe
│   ├── 7z.exe
│   ├── wget.exe
│   ├── curl.exe
│   └── jq.exe
│
└── lib\                         # Installed packages

C:\Program Files\
├── Sysinternals\
│   ├── procmon.exe
│   ├── procexp.exe
│   ├── autoruns.exe
│   └── [50+ tools]
│
├── Process Hacker 2\
├── x64dbg\
├── ILSpy\
├── Docker\
├── Oracle\VirtualBox\
└── Wireshark\

C:\Program Files (x86)\
├── Nmap\
└── OWASP\ZAP\
```

### Python Packages Location
```
C:\Python311\                    # Python installation
│
├── python.exe
├── Scripts\                     # Python scripts (in PATH)
│   ├── pip.exe
│   ├── impacket-*
│   ├── crackmapexec.exe
│   ├── bloodhound.py
│   ├── arjun
│   └── xsstrike
│
└── Lib\site-packages\           # Python packages
```

### Nuclei Templates Location
```
C:\Users\YourUsername\nuclei-templates\
│
├── cves\                        # CVE templates (2000+)
├── vulnerabilities\             # Generic vulnerabilities
├── exposed-panels\              # Exposed admin panels
├── exposed-tokens\              # Exposed tokens/keys
├── misconfigurations\           # Misconfigurations
├── takeovers\                   # Subdomain takeovers
├── default-logins\              # Default credentials
└── workflows\                   # Multi-step workflows
```

### Bug Bounty Directory Structure
```
C:\Users\YourUsername\bug-bounty\
│
├── recon\                       # Reconnaissance results
│   ├── subdomains\
│   ├── urls\
│   └── ports\
│
├── scanning\                    # Vulnerability scans
│   ├── nuclei\
│   ├── burp\
│   └── zap\
│
├── exploitation\                # Exploitation attempts
│   ├── poc\
│   └── payloads\
│
└── reporting\                   # Reports and writeups
    ├── submissions\
    └── screenshots\
```

### Log File Location
```
C:\Users\YourUsername\security-tools-install.log
```

Example log content:
```
[2024-01-15 14:32:10] Installation started - Windows-specific tools only
[2024-01-15 14:32:15] SUCCESS: Chocolatey installed successfully
[2024-01-15 14:35:22] SUCCESS: git installed
[2024-01-15 14:38:45] SUCCESS: python installed
...
```

---

## ✨ Post-Installation Steps

### Step 1: Verify Installation

Open a **new** PowerShell window (close and reopen) and run:

```powershell
# Test ADB
adb version
# Expected output: Android Debug Bridge version 1.0.41

# Test Go tools
nuclei -version
# Expected output: Nuclei - Open-source project (github.com/projectdiscovery/nuclei)

subfinder -version
# Expected output: Subfinder v2.x.x

httpx -version
# Expected output: httpx v1.x.x

ffuf -V
# Expected output: ffuf version v2.x.x

# Test Python tools
python --version
# Expected output: Python 3.11.x

python -m pip list | Select-String -Pattern "impacket"
# Expected output: impacket   0.x.x

python -m pip list | Select-String -Pattern "crackmapexec"
# Expected output: crackmapexec   5.x.x

# Test PATH configuration
$env:Path -split ";" | Select-String -Pattern "go\\bin"
# Expected output: C:\Users\YourUsername\go\bin

$env:Path -split ";" | Select-String -Pattern "platform-tools"
# Expected output: C:\Users\YourUsername\security-tools\platform-tools

# Verify Chocolatey
choco --version
# Expected output: 2.x.x

# Check installed Chocolatey packages
choco list --local-only
```

---

### Step 2: Complete Burp Suite Installation

Burp Suite Community Edition was downloaded but requires manual installation:

```powershell
# Navigate to installation file
cd $env:USERPROFILE\security-tools

# Run installer
.\burpsuite_community_windows-x64.exe
```

**Installation Steps**:
1. Click "Next" through the installation wizard
2. Accept the license agreement
3. Choose installation directory (default is fine)
4. Select "Create desktop shortcut"
5. Click "Install"
6. Launch Burp Suite
7. Choose "Temporary project" for first run
8. Use Burp defaults

---

### Step 3: Setup Android Studio

Android Studio requires additional configuration:

```powershell
# Launch Android Studio
# It should be in Start Menu
```

**Setup Steps**:
1. **Welcome Screen**: Click "Next"
2. **Install Type**: Choose "Standard" → Next
3. **UI Theme**: Choose your preference → Next
4. **SDK Components**: Verify these are selected:
   - Android SDK
   - Android SDK Platform
   - Android Virtual Device
5. **License Agreement**: Accept all → Finish
6. **Download Components**: Wait for download (2-5 GB)

**Configure SDK Manager**:
1. Open Android Studio
2. Click "More Actions" → "SDK Manager"
3. **SDK Platforms** tab:
   - Install latest Android version
   - Install Android 11 (API 30) - most compatible
4. **SDK Tools** tab:
   - ✅ Android SDK Build-Tools
   - ✅ Android SDK Platform-Tools (already installed via script)
   - ✅ Android Emulator
   - ✅ Intel x86 Emulator Accelerator (HAXM installer)
5. Click "Apply" → "OK"

**Create Virtual Device** (Optional):
1. Click "More Actions" → "AVD Manager"
2. Click "Create Virtual Device"
3. Select hardware (e.g., Pixel 4)
4. Select system image (e.g., Android 11)
5. Click "Finish"

---

### Step 4: Update Nuclei Templates

Nuclei templates are updated frequently with new vulnerabilities:

```powershell
# Update to latest templates
nuclei -update-templates

# Expected output:
# [INF] Downloading nuclei-templates...
# [INF] Successfully downloaded nuclei-templates (vX.X.X)

# Verify templates
nuclei -tl
# Shows list of all templates

# Count templates
nuclei -tl | Measure-Object -Line
# Should show 3000+ templates
```

---

### Step 5: Connect Android Device via ADB

**Enable Developer Options on Android**:
1. Go to **Settings** → **About Phone**
2. Tap **"Build Number"** 7 times
3. Message: "You are now a developer!"

**Enable USB Debugging**:
1. Go to **Settings** → **Developer Options**
2. Enable **"USB Debugging"**
3. Enable **"Install via USB"** (optional)

**Connect Device**:
```powershell
# Connect phone via USB cable

# Verify connection
adb devices

# First time connection - phone will show prompt
# Tap "Allow" on phone

# Verify again
adb devices
# Expected output:
# List of devices attached
# 1234567890ABCDEF    device
```

**Wireless ADB Connection** (Optional):
```powershell
# Connect device via USB first
adb devices

# Enable TCP/IP mode on port 5555
adb tcpip 5555

# Find device IP address
# On phone: Settings → About Phone → Status → IP Address
# Example: 192.168.1.100

# Connect wirelessly
adb connect 192.168.1.100:5555

# Disconnect USB cable - device should remain connected

# Verify
adb devices
# Expected output:
# List of devices attached
# 192.168.1.100:5555    device
```

---

### Step 6: Test Docker (for MobSF)

MobSF (Mobile Security Framework) runs in Docker:

```powershell
# Start Docker Desktop
# Find "Docker Desktop" in Start Menu and launch

# Wait for Docker to fully start (watch system tray icon)

# Verify Docker is running
docker --version
# Expected output: Docker version 24.x.x

# Pull MobSF image
docker pull opensecurity/mobile-security-framework-mobsf
# This downloads ~2GB - takes 5-10 minutes

# Run MobSF
docker run -it -p 8000:8000 opensecurity/mobile-security-framework-mobsf

# Access MobSF web interface
# Open browser: http://localhost:8000

# Stop MobSF: Press Ctrl+C in PowerShell
```

**MobSF Usage**:
1. Open http://localhost:8000 in browser
2. Drag and drop APK file to upload
3. Click on uploaded APK to analyze
4. View analysis results:
   - Permissions
   - Security issues
   - Code analysis
   - Malware check

---

### Step 7: Restart PowerShell

After installation, restart PowerShell to ensure PATH changes take effect:

```powershell
# Method 1: Close and reopen PowerShell

# Method 2: Reload environment variables in current session
refreshenv

# Method 3: Manually reload PATH
$env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
```

---

### Step 8: Create Shortcuts (Optional)

Create desktop shortcuts for frequently used tools:

```powershell
# Create shortcuts directory
$shortcutsPath = "$env:USERPROFILE\Desktop\SecurityTools"
New-Item -ItemType Directory -Force -Path $shortcutsPath

# Function to create shortcut
function Create-Shortcut {
    param($Name, $TargetPath, $Arguments = "")
    $WScriptShell = New-Object -ComObject WScript.Shell
    $Shortcut = $WScriptShell.CreateShortcut("$shortcutsPath\$Name.lnk")
    $Shortcut.TargetPath = $TargetPath
    $Shortcut.Arguments = $Arguments
    $Shortcut.Save()
}

# Create shortcuts
Create-Shortcut "Process Monitor" "C:\ProgramData\chocolatey\lib\sysinternals\tools\procmon.exe"
Create-Shortcut "Process Explorer" "C:\ProgramData\chocolatey\lib\sysinternals\tools\procexp.exe"
Create-Shortcut "JADX" "$env:USERPROFILE\security-tools\jadx\bin\jadx-gui.bat"
Create-Shortcut "dnSpy" "$env:USERPROFILE\security-tools\dnspy\dnSpy.exe"
Create-Shortcut "Ghidra" "$env:USERPROFILE\security-tools\ghidra\ghidra_*\ghidraRun.bat"
Create-Shortcut "Burp Suite" "$env:USERPROFILE\AppData\Local\Programs\BurpSuiteCommunity\BurpSuiteCommunity.exe"
Create-Shortcut "OWASP ZAP" "C:\Program Files (x86)\OWASP\Zed Attack Proxy\ZAP.exe"
```

---

## 🎓 Tool Usage Examples

### Subdomain Enumeration

**Basic Subdomain Enumeration**:
```powershell
# Using Subfinder
subfinder -d example.com -o subdomains.txt

# Using Subfinder with all sources
subfinder -d example.com -all -recursive -o subdomains_all.txt

# Using Amass
amass enum -d example.com -o amass_results.txt

# Using Amass with passive mode (faster)
amass enum -passive -d example.com -o amass_passive.txt

# Using Sublist3r (Python)
python -m sublist3r -d example.com -o sublist3r_results.txt
```

**Advanced Subdomain Enumeration**:
```powershell
# Combine multiple tools
subfinder -d example.com -silent | `
amass enum -passive -d example.com | `
anew all_subdomains.txt

# Brute force subdomains
ffuf -u https://FUZZ.example.com -w $env:USERPROFILE\security-tools\wordlists\SecLists\Discovery\DNS\subdomains-top1million-110000.txt -mc 200,301,302,403

# DNS resolution
cat subdomains.txt | dnsx -silent -o resolved_subdomains.txt
```

---

### Web Reconnaissance

**Check Live Hosts**:
```powershell
# Probe HTTP/HTTPS
cat subdomains.txt | httpx -silent -o alive_hosts.txt

# Probe with status codes
cat subdomains.txt | httpx -status-code -title -tech-detect -o alive_hosts_detailed.txt

# Probe specific ports
cat subdomains.txt | httpx -ports 80,443,8080,8443 -o alive_ports.txt
```

**Web Crawling**:
```powershell
# Crawl with Katana
katana -u https://example.com -o urls.txt

# Crawl with depth limit
katana -u https://example.com -depth 3 -o urls_depth3.txt

# Crawl JavaScript files
katana -u https://example.com -js-crawl -o js_urls.txt

# Crawl with Gospider
gospider -s https://example.com -o gospider_output

# Crawl with Hakrawler
echo "https://example.com" | hakrawler -o hakrawler_urls.txt
```

**URL Discovery**:
```powershell
# Get URLs from Wayback Machine
echo "example.com" | waybackurls > wayback_urls.txt

# Get URLs from multiple sources
echo "example.com" | gau --threads 5 --o gau_urls.txt

# Combine all URL sources
cat wayback_urls.txt gau_urls.txt katana_urls.txt | anew all_urls.txt
```

**Directory Fuzzing**:
```powershell
# Basic directory fuzzing with ffuf
ffuf -u https://example.com/FUZZ -w $env:USERPROFILE\security-tools\wordlists\SecLists\Discovery\Web-Content\directory-list-2.3-medium.txt -o ffuf_results.json

# Directory fuzzing with extensions
ffuf -u https://example.com/FUZZ -w $env:USERPROFILE\security-tools\wordlists\SecLists\Discovery\Web-Content\raft-large-files.txt -e .php,.html,.txt,.bak -o ffuf_files.json

# Gobuster directory brute-force
gobuster dir -u https://example.com -w $env:USERPROFILE\security-tools\wordlists\SecLists\Discovery\Web-Content\common.txt -o gobuster_results.txt

# Gobuster with extensions
gobuster dir -u https://example.com -w $env:USERPROFILE\security-tools\wordlists\SecLists\Discovery\Web-Content\common.txt -x php,html,txt,bak -o gobuster_ext.txt
```

---

### Vulnerability Scanning

**Nuclei - Automated Vulnerability Scanning**:
```powershell
# Basic scan
nuclei -u https://example.com -o nuclei_results.txt

# Scan multiple targets
nuclei -l alive_hosts.txt -o nuclei_scan.txt

# Scan with specific templates
nuclei -l alive_hosts.txt -t $env:USERPROFILE\nuclei-templates\cves\ -o nuclei_cves.txt

# Scan with severity filter
nuclei -l alive_hosts.txt -severity critical,high -o nuclei_critical.txt

# Scan with tags
nuclei -l alive_hosts.txt -tags xss,sqli,rce -o nuclei_tagged.txt

# Scan with rate limiting
nuclei -l alive_hosts.txt -rate-limit 50 -o nuclei_ratelimited.txt

# Scan and send notifications
nuclei -l alive_hosts.txt -severity critical -notify
```

**XSS Scanning**:
```powershell
# Find XSS parameters
cat urls.txt | kxss -o xss_params.txt

# Scan for XSS with Dalfox
cat urls.txt | dalfox pipe -o xss_vulnerabilities.txt

# Dalfox with custom payloads
dalfox url https://example.com/search?q=FUZZ --custom-payload "<script>alert(1)</script>" -o dalfox_results.txt

# XSStrike (Python)
python -m xsstrike -u "https://example.com/search?q=test"
```

**CRLF Injection**:
```powershell
# Scan for CRLF injection
crlfuzz -l urls.txt -o crlf_results.txt
```

**Parameter Discovery**:
```powershell
# Discover parameters with Arjun
python -m arjun -u https://example.com/api/user

# Arjun on multiple URLs
arjun -i urls.txt -o arjun_params.json
```

---

### Android Application Testing

**Install and Setup**:
```powershell
# List connected devices
adb devices

# Install APK
adb install app.apk

# Install APK (replace if exists)
adb install -r app.apk

# Uninstall app
adb uninstall com.example.app
```

**APK Analysis**:
```powershell
# Decompile APK with JADX
jadx app.apk -d output_folder

# Decompile with JADX-GUI (graphical interface)
jadx-gui app.apk

# Reverse engineer with APKTool
apktool d app.apk -o app_source

# Rebuild APK after modifications
apktool b app_source -o modified.apk

# Sign APK
# (Requires jarsigner - included in Java JDK)
```

**Dynamic Analysis**:
```powershell
# Start app
adb shell am start -n com.example.app/.MainActivity

# View logcat
adb logcat

# Filter logcat
adb logcat | Select-String -Pattern "example"

# Clear logcat
adb logcat -c

# Dump app data
adb shell pm dump com.example.app
```

**Screen Mirroring**:
```powershell
# Mirror device screen
scrcpy

# Mirror with specific bitrate
scrcpy --bit-rate 2M

# Mirror and record
scrcpy --record screen_recording.mp4

# Mirror specific device (if multiple connected)
scrcpy --serial DEVICE_ID
```

**File Operations**:
```powershell
# Pull file from device
adb pull /sdcard/file.txt

# Push file to device
adb push file.txt /sdcard/

# Pull app APK
adb shell pm path com.example.app
# Output: package:/data/app/com.example.app-1/base.apk
adb pull /data/app/com.example.app-1/base.apk

# Backup app data
adb backup -f backup.ab com.example.app
```

**MobSF Analysis**:
```powershell
# Start MobSF
docker run -it -p 8000:8000 opensecurity/mobile-security-framework-mobsf

# Access web interface
start http://localhost:8000

# Upload APK through web interface
# Analysis includes:
#   - Static analysis
#   - Manifest analysis
#   - Code analysis
#   - Binary analysis
#   - Malware detection
```

---

### Secret Scanning

**Gitleaks - Secret Detection**:
```powershell
# Scan current directory
gitleaks detect --source . --verbose

# Scan with report
gitleaks detect --source . --report-path leaks.json

# Scan specific Git repository
gitleaks detect --source C:\path\to\repo --verbose

# Scan remote repository
gitleaks detect --source https://github.com/example/repo

# Scan and baseline (future scans only show new secrets)
gitleaks detect --source . --baseline-path baseline.json
```

**TruffleHog - Credential Scanning**:
```powershell
# Scan Git repository
trufflehog git https://github.com/example/repo

# Scan local repository
trufflehog filesystem C:\path\to\repo

# Scan with JSON output
trufflehog git https://github.com/example/repo --json > trufflehog_results.json

# Scan only recent commits
trufflehog git https://github.com/example/repo --since-commit abc123
```

---

### Windows Binary Analysis

**Detect It Easy - PE File Analysis**:
```powershell
# Analyze PE file
$env:USERPROFILE\security-tools\detect-it-easy\die.exe suspicious.exe

# Console mode
$env:USERPROFILE\security-tools\detect-it-easy\diec.exe suspicious.exe
```

**dnSpy - .NET Decompilation**:
```powershell
# Open dnSpy
$env:USERPROFILE\security-tools\dnspy\dnSpy.exe

# Load assembly through GUI
# File → Open → Select .exe or .dll
```

**x64dbg - Windows Debugging**:
```powershell
# Launch x64dbg
x64dbg.exe

# Or debug specific executable
x64dbg.exe target.exe
```

**Sysinternals Tools**:
```powershell
# Process Monitor (monitor file system, registry, network activity)
procmon.exe

# Process Explorer (enhanced task manager)
procexp.exe

# Autoruns (startup programs)
autoruns.exe

# TCPView (network connections)
tcpview.exe

# Strings (extract strings from binary)
strings.exe suspicious.exe

# PsExec (remote execution)
psexec.exe \\remote-computer cmd.exe
```

---

### Network Analysis

**Nmap - Port Scanning**:
```powershell
# Basic scan
nmap example.com

# Scan specific ports
nmap -p 80,443,8080 example.com

# Service version detection
nmap -sV example.com

# OS detection
nmap -O example.com

# Aggressive scan
nmap -A example.com

# Scan from file
nmap -iL targets.txt

# Output to file
nmap example.com -oN nmap_output.txt
```

**Wireshark - Packet Capture**:
```powershell
# Launch Wireshark
wireshark.exe

# Capture on specific interface
# Select interface from GUI
```

---

### Active Directory / Windows Pentesting

**Impacket Tools**:
```powershell
# SMB enumeration
python -m impacket.smbclient domain/user:password@target

# Get TGT (Kerberos ticket)
python -m impacket.getTGT domain/user:password

# PSExec (remote command execution)
python -m impacket.psexec domain/user:password@target

# SecretsDump (extract credentials)
python -m impacket.secretsdump domain/user:password@target

# GetNPUsers (ASREProast)
python -m impacket.GetNPUsers domain/ -usersfile users.txt -dc-ip 10.10.10.10
```

**CrackMapExec**:
```powershell
# SMB enumeration
crackmapexec smb 192.168.1.0/24

# SMB with credentials
crackmapexec smb 192.168.1.100 -u user -p password

# Enumerate shares
crackmapexec smb 192.168.1.100 -u user -p password --shares

# Execute command
crackmapexec smb 192.168.1.100 -u user -p password -x "whoami"

# Dump SAM
crackmapexec smb 192.168.1.100 -u user -p password --sam
```

**Responder - LLMNR/NBT-NS Poisoning**:
```powershell
# Start Responder
python -m responder -I eth0 -wrf
```

---

### Reporting & Output Management

**Filtering and Sorting Results**:
```powershell
# Remove duplicates
cat urls.txt | anew unique_urls.txt

# Sort and count
cat urls.txt | Sort-Object | Get-Unique | Measure-Object -Line

# Filter by pattern
cat urls.txt | Select-String -Pattern "admin"

# Exclude patterns
cat urls.txt | Select-String -Pattern "logout" -NotMatch

# Save filtered results
cat urls.txt | Select-String -Pattern "api" > api_urls.txt
```

**URL Manipulation**:
```powershell
# Parse URLs
cat urls.txt | unfurl format "%s://%d%p"

# Extract domains
cat urls.txt | unfurl domains

# Extract paths
cat urls.txt | unfurl paths

# Replace query parameters
cat urls.txt | qsreplace "FUZZ"
```

---

## 🔧 Troubleshooting

### Issue 1: "Execution Policy" Error

**Error Message**:
```
.\Install-WindowsSecurityTools.ps1 : File cannot be loaded because running scripts is disabled on this system.
```

**Solution**:
```powershell
# Set execution policy for current session
Set-ExecutionPolicy Bypass -Scope Process -Force

# Then run the script again
.\Install-WindowsSecurityTools.ps1
```

**Alternative Solution** (if above doesn't work):
```powershell
# Run script with bypass flag
powershell.exe -ExecutionPolicy Bypass -File .\Install-WindowsSecurityTools.ps1
```

---

### Issue 2: Chocolatey Installation Failed

**Error Message**:
```
Failed to install Chocolatey
```

**Solution - Manual Chocolatey Installation**:
```powershell
# Step 1: Set TLS protocol
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072

# Step 2: Download and install
Set-ExecutionPolicy Bypass -Scope Process -Force
iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

# Step 3: Verify installation
choco --version

# Step 4: Re-run main script
.\Install-WindowsSecurityTools.ps1
```

**Alternative - Check Prerequisites**:
```powershell
# Check .NET Framework version
Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' | Select-Object Version

# Should be 4.5 or higher
# If not, download and install .NET Framework 4.8:
# https://dotnet.microsoft.com/download/dotnet-framework/net48
```

---

### Issue 3: Go Tools Not Found

**Error Message**:
```
'nuclei' is not recognized as an internal or external command
```

**Solution - Add Go bin to PATH**:
```powershell
# Check if Go is installed
go version

# If Go is installed, add bin directory to PATH
$goPath = "$env:USERPROFILE\go\bin"
$env:Path += ";$goPath"

# Make permanent
[Environment]::SetEnvironmentVariable("Path", $env:Path, "User")

# Restart PowerShell
exit
# Then open new PowerShell window

# Verify
nuclei -version
```

**Alternative - Reinstall Go Tools**:
```powershell
# Reinstall all Go tools
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/ffuf/ffuf/v2@latest
# ... etc
```

---

### Issue 4: ADB Not Recognized

**Error Message**:
```
'adb' is not recognized as an internal or external command
```

**Solution - Add platform-tools to PATH**:
```powershell
# Add platform-tools to PATH
$adbPath = "$env:USERPROFILE\security-tools\platform-tools"
$env:Path += ";$adbPath"

# Make permanent
[Environment]::SetEnvironmentVariable("Path", $env:Path, "User")

# Restart PowerShell
exit

# Verify
adb version
```

**Verify Installation**:
```powershell
# Check if platform-tools directory exists
Test-Path "$env:USERPROFILE\security-tools\platform-tools\adb.exe"
# Should return: True

# If False, re-download platform-tools
$url = "https://dl.google.com/android/repository/platform-tools-latest-windows.zip"
$output = "$env:USERPROFILE\Downloads\platform-tools.zip"
Invoke-WebRequest -Uri $url -OutFile $output
Expand-Archive -Path $output -DestinationPath "$env:USERPROFILE\security-tools\" -Force
```

---

### Issue 5: Python Tools Not Found

**Error Message**:
```
'python' is not recognized as an internal or external command
```

**Solution - Verify Python Installation**:
```powershell
# Check if Python is installed
python --version

# If not installed, install via Chocolatey
choco install python -y

# Restart PowerShell
exit

# Verify installation
python --version
pip --version
```

**Add Python to PATH manually**:
```powershell
# Find Python installation
Get-ChildItem -Path C:\Python* -Directory

# Add to PATH (adjust version number)
$pythonPath = "C:\Python311;C:\Python311\Scripts"
$env:Path += ";$pythonPath"
[Environment]::SetEnvironmentVariable("Path", $env:Path, "User")

# Restart PowerShell
```

**Reinstall Python packages**:
```powershell
# Upgrade pip
python -m pip install --upgrade pip

# Reinstall tools
python -m pip install impacket crackmapexec arjun xsstrike sublist3r
```

---

### Issue 6: Docker Desktop Won't Start

**Error Message**:
```
Docker Desktop failed to start
```

**Solution 1 - Enable WSL2**:
```powershell
# Install WSL2
wsl --install

# Restart computer
shutdown /r /t 0

# After restart, verify WSL2
wsl --status

# Start Docker Desktop
```

**Solution 2 - Enable Hyper-V**:
```powershell
# Enable Hyper-V
Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All

# Restart computer
shutdown /r /t 0

# Start Docker Desktop after restart
```

**Solution 3 - Reset Docker Desktop**:
```powershell
# Uninstall Docker Desktop
choco uninstall docker-desktop -y

# Remove Docker data
Remove-Item -Recurse -Force "$env:APPDATA\Docker"
Remove-Item -Recurse -Force "$env:LOCALAPPDATA\Docker"

# Reinstall Docker Desktop
choco install docker-desktop -y

# Restart computer
shutdown /r /t 0
```

---

### Issue 7: Antivirus Blocking Tools

**Symptoms**:
- Tools download but immediately disappear
- Installation fails with "Access Denied"
- Tools flagged as malware

**Solution - Add Exclusions**:

**Windows Defender**:
```powershell
# Add exclusions via PowerShell (Run as Admin)
Add-MpPreference -ExclusionPath "$env:USERPROFILE\security-tools"
Add-MpPreference -ExclusionPath "$env:USERPROFILE\go\bin"
Add-MpPreference -ExclusionPath "C:\ProgramData\chocolatey"

# Verify exclusions
Get-MpPreference | Select-Object -ExpandProperty ExclusionPath
```

**Windows Defender (GUI)**:
1. Open Windows Security
2. Virus & threat protection
3. Manage settings
4. Add or remove exclusions
5. Add folders:
   - `C:\Users\YourUsername\security-tools`
   - `C:\Users\YourUsername\go\bin`
   - `C:\ProgramData\chocolatey`

**Third-Party Antivirus**:
- Temporarily disable real-time protection during installation
- Add same folders to exclusion list
- Re-enable after installation

---

### Issue 8: Installation Hanging/Slow

**Symptoms**:
- Installation stuck at a particular tool
- Very slow downloads
- Timeouts

**Solutions**:

**Check Internet Connection**:
```powershell
# Test connectivity
Test-Connection google.com -Count 4

# Test download speed
Invoke-WebRequest -Uri "http://speedtest.com" -UseBasicParsing
```

**Disable VPN**:
```powershell
# VPNs can cause issues with some downloads
# Temporarily disable VPN during installation
```

**Free Up Disk Space**:
```powershell
# Check disk space
Get-PSDrive C | Select-Object Used,Free

# Clean temporary files
Remove-Item -Path "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue

# Run Disk Cleanup
cleanmgr.exe
```

**Close Other Applications**:
```powershell
# Close browsers, IDEs, and other heavy applications
# to free up RAM and network bandwidth
```

**Run During Off-Peak Hours**:
- Large downloads (Chocolatey packages, Docker images) are faster during off-peak hours
- Consider running installation overnight

---

### Issue 9: Some Tools Failed to Install

**Check Log File**:
```powershell
# View log file
notepad $env:USERPROFILE\security-tools-install.log

# Search for errors
Select-String -Path "$env:USERPROFILE\security-tools-install.log" -Pattern "ERROR|Failed"
```

**Manually Install Failed Tools**:

**If Nuclei failed**:
```powershell
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

**If Impacket failed**:
```powershell
python -m pip install impacket
```

**If Chocolatey package failed**:
```powershell
choco install package-name -y
```

**Retry Installation**:
```powershell
# Re-run the script
# It will skip already-installed tools
.\Install-WindowsSecurityTools.ps1
```

---

### Issue 10: Git Clone Failures

**Error Message**:
```
fatal: unable to access 'https://github.com/...': Failed to connect
```

**Solution - Configure Git Proxy**:
```powershell
# If behind corporate proxy
git config --global http.proxy http://proxy.example.com:8080
git config --global https.proxy https://proxy.example.com:8080

# Remove proxy (if not needed)
git config --global --unset http.proxy
git config --global --unset https.proxy
```

**Solution - Increase Git Buffer**:
```powershell
# Increase buffer size for large repositories
git config --global http.postBuffer 524288000

# Increase timeout
git config --global http.lowSpeedLimit 0
git config --global http.lowSpeedTime 999999
```

---

### Issue 11: Nuclei Templates Not Updating

**Error Message**:
```
[ERR] Could not update nuclei-templates
```

**Solution**:
```powershell
# Remove old templates
Remove-Item -Recurse -Force "$env:USERPROFILE\nuclei-templates"

# Re-download templates
nuclei -update-templates

# Verify
nuclei -tl | Measure-Object -Line
# Should show 3000+ templates
```

---

### Issue 12: Android Studio SDK Issues

**Problem**: SDK Manager won't download components

**Solution**:
```powershell
# Check SDK location
$env:ANDROID_SDK_ROOT

# If not set, set it manually
$env:ANDROID_SDK_ROOT = "$env:LOCALAPPDATA\Android\Sdk"
[Environment]::SetEnvironmentVariable("ANDROID_SDK_ROOT", $env:ANDROID_SDK_ROOT, "User")

# Download SDK manually
# Open Android Studio → SDK Manager → Install components
```

---

### Issue 13: PATH Too Long Error

**Error Message**:
```
The environment variable PATH is too long
```

**Solution - Clean PATH**:
```powershell
# View current PATH
$env:Path -split ";"

# Remove duplicates and clean PATH
$paths = $env:Path -split ";" | Select-Object -Unique | Where-Object { $_ -ne "" }
$cleanPath = $paths -join ";"
[Environment]::SetEnvironmentVariable("Path", $cleanPath, "User")

# Restart PowerShell
```

---

### Issue 14: Burp Suite Won't Launch

**Problem**: Burp Suite Community Edition doesn't start

**Solution - Check Java**:
```powershell
# Burp requires Java
java -version

# If Java not installed
choco install openjdk -y

# Restart computer
shutdown /r /t 0

# Try launching Burp again
```

---

### Issue 15: Permission Denied Errors

**Error Message**:
```
Access to the path is denied
```

**Solution - Run as Administrator**:
```powershell
# Always run PowerShell as Administrator
# Right-click PowerShell → "Run as Administrator"
```

**Solution - Check File Permissions**:
```powershell
# Check folder permissions
Get-Acl "$env:USERPROFILE\security-tools" | Format-List

# Take ownership
takeown /f "$env:USERPROFILE\security-tools" /r /d y

# Grant permissions
icacls "$env:USERPROFILE\security-tools" /grant "$env:USERNAME:(OI)(CI)F" /t
```

---

## 📚 Complete Tool List

### Windows-Specific Tools (6 tools)

| Tool | Description | Usage | Location |
|------|-------------|-------|----------|
| **Sysinternals Suite** | 70+ Windows system utilities | `procmon.exe`, `procexp.exe`, `autoruns.exe` | `C:\ProgramData\chocolatey\lib\sysinternals\tools\` |
| **Process Hacker** | Advanced process monitoring tool | `ProcessHacker.exe` | `C:\Program Files\Process Hacker 2\` |
| **x64dbg** | Open-source x64/x32 debugger | `x64dbg.exe` | `C:\Program Files\x64dbg\` |
| **dnSpy** | .NET debugger and assembly editor | `dnSpy.exe` | `%USERPROFILE%\security-tools\dnspy\` |
| **ILSpy** | .NET decompiler | `ILSpy.exe` | `C:\Program Files\ILSpy\` |
| **Detect It Easy** | PE file analyzer and detector | `die.exe` | `%USERPROFILE%\security-tools\detect-it-easy\` |

---

### Go Security Tools (24 tools)

#### ProjectDiscovery Suite (8 tools)
| Tool | Description | Usage Example |
|------|-------------|---------------|
| **nuclei** | Vulnerability scanner based on templates | `nuclei -u https://example.com` |
| **subfinder** | Subdomain discovery tool | `subfinder -d example.com` |
| **httpx** | HTTP toolkit for probing | `cat domains.txt \| httpx` |
| **katana** | Next-generation web crawler | `katana -u https://example.com` |
| **naabu** | Fast port scanner | `naabu -host example.com` |
| **dnsx** | DNS toolkit | `dnsx -l domains.txt` |
| **interactsh** | OOB interaction tool | `interactsh-client` |
| **notify** | Multi-channel notification system | `nuclei ... \| notify` |

#### Fuzzing Tools (2 tools)
| Tool | Description | Usage Example |
|------|-------------|---------------|
| **ffuf** | Fast web fuzzer | `ffuf -u https://example.com/FUZZ -w wordlist.txt` |
| **gobuster** | Directory/DNS/vhost brute-forcer | `gobuster dir -u https://example.com -w wordlist.txt` |

#### Discovery Tools (6 tools)
| Tool | Description | Usage Example |
|------|-------------|---------------|
| **amass** | In-depth subdomain enumeration | `amass enum -d example.com` |
| **assetfinder** | Find domains and subdomains | `assetfinder example.com` |
| **gau** | Fetch known URLs from multiple sources | `echo example.com \| gau` |
| **waybackurls** | Fetch URLs from Wayback Machine | `echo example.com \| waybackurls` |
| **hakrawler** | Simple, fast web crawler | `echo https://example.com \| hakrawler` |
| **gospider** | Fast web spider | `gospider -s https://example.com` |

#### Utility Tools (4 tools)
| Tool | Description | Usage Example |
|------|-------------|---------------|
| **gf** | Wrapper for grep with security patterns | `cat urls.txt \| gf xss` |
| **anew** | Add new lines to files (deduplicate) | `cat new.txt \| anew old.txt` |
| **unfurl** | Pull out bits of URLs | `cat urls.txt \| unfurl domains` |
| **qsreplace** | Replace query string values | `cat urls.txt \| qsreplace FUZZ` |

#### Security Tools (4 tools)
| Tool | Description | Usage Example |
|------|-------------|---------------|
| **dalfox** | XSS scanner and parameter analyzer | `dalfox url https://example.com?q=test` |
| **kxss** | Find Reflected XSS parameters | `cat urls.txt \| kxss` |
| **crlfuzz** | CRLF injection scanner | `crlfuzz -l urls.txt` |
| **gitleaks** | Scan for secrets in git repos | `gitleaks detect --source .` |
| **trufflehog** | Find credentials in code | `trufflehog git https://github.com/user/repo` |

---

### Python Security Tools (19 tools)

#### Windows/AD Pentesting (8 tools)
| Tool | Description | Usage Example |
|------|-------------|---------------|
| **impacket** | Collection of Python classes for network protocols | `python -m impacket.psexec` |
| **crackmapexec** | Swiss army knife for Windows/AD pentesting | `crackmapexec smb 192.168.1.0/24` |
| **bloodhound** | AD attack path analysis | `bloodhound.py -u user -p pass -d domain.com` |
| **mitm6** | IPv6 MITM attack tool | `mitm6 -d domain.com` |
| **responder** | LLMNR/NBT-NS/MDNS poisoner | `responder -I eth0` |
| **pywerview** | PowerView Python implementation | `pywerview -u user -p pass` |
| **ldapdomaindump** | AD information dumper | `ldapdomaindump -u user -p pass` |
| **kerbrute** | Kerberos pre-auth bruteforcing | `kerbrute userenum --dc 10.10.10.10` |

#### Web Application Testing (3 tools)
| Tool | Description | Usage Example |
|------|-------------|---------------|
| **arjun** | HTTP parameter discovery | `arjun -u https://example.com/api` |
| **xsstrike** | Advanced XSS detection suite | `xsstrike -u "https://example.com?q=test"` |
| **sublist3r** | Subdomain enumeration tool | `sublist3r -d example.com` |

#### Libraries & APIs (8 tools)
| Tool | Description | Purpose |
|------|-------------|---------|
| **requests** | HTTP library | Making HTTP requests |
| **beautifulsoup4** | HTML/XML parser | Web scraping |
| **selenium** | Browser automation | Dynamic content testing |
| **playwright** | Browser automation framework | Modern web testing |
| **pycryptodome** | Cryptographic library | Encryption/decryption |
| **pyjwt** | JWT implementation | JWT token handling |
| **shodan** | Shodan API client | Internet-wide scanning |
| **censys** | Censys API client | Certificate/host search |

---

### Web Application Security (2 tools)

| Tool | Description | Usage | License |
|------|-------------|-------|---------|
| **Burp Suite Community** | Web vulnerability scanner and proxy | Manual install required | Free |
| **OWASP ZAP** | Web application security scanner | `zap.bat` or GUI | Free |

---

### Android Security Tools (7 tools)

| Tool | Description | Usage Example | Location |
|------|-------------|---------------|----------|
| **ADB** | Android Debug Bridge | `adb devices` | `%USERPROFILE%\security-tools\platform-tools\` |
| **Fastboot** | Android fastboot utility | `fastboot devices` | `%USERPROFILE%\security-tools\platform-tools\` |
| **Android Studio** | Official Android IDE | Launch from Start Menu | `C:\Program Files\Android\Android Studio\` |
| **JADX** | Dex to Java decompiler | `jadx app.apk -d output` | `%USERPROFILE%\security-tools\jadx\` |
| **APKTool** | APK reverse engineering tool | `apktool d app.apk` | `%USERPROFILE%\security-tools\apktool\` |
| **scrcpy** | Display and control Android devices | `scrcpy` | System PATH |
| **MobSF** | Mobile Security Framework | `docker run -p 8000:8000 mobsf` | Docker |

---

### Reverse Engineering Tools (2 tools)

| Tool | Description | Usage | Location |
|------|-------------|-------|----------|
| **Ghidra** | NSA reverse engineering framework | `ghidraRun.bat` | `%USERPROFILE%\security-tools\ghidra\` |
| **IDA Free** | Binary code analyzer | Download from hex-rays.com | Manual download |

---

### Wordlists (2 collections)

| Collection | Description | Size | Location |
|------------|-------------|------|----------|
| **SecLists** | Security testing wordlists | 40,000+ files | `%USERPROFILE%\security-tools\wordlists\SecLists\` |
| **PayloadsAllTheThings** | Useful payloads and bypasses | 1,000+ files | `%USERPROFILE%\security-tools\wordlists\PayloadsAllTheThings\` |

**SecLists Categories**:
- Discovery (web content, DNS, infrastructure)
- Passwords (common passwords, leaked databases)
- Usernames (common usernames)
- Fuzzing (injection payloads, XSS, SQLi)
- Pattern Matching (regex patterns)
- Miscellaneous (IOCs, malware, vulnerabilities)

**PayloadsAllTheThings Categories**:
- XSS Injection
- SQL Injection
- Command Injection
- File Upload
- XXE Injection
- SSRF
- Path Traversal
- CSRF
- Deserialization
- SSTI

---

### System Dependencies (11 tools)

| Tool | Description | Version | Usage |
|------|-------------|---------|-------|
| **Git** | Version control system | Latest | `git clone`, `git pull` |
| **Python 3** | Programming language | 3.11+ | `python script.py` |
| **Go** | Programming language | 1.21+ | `go install`, `go run` |
| **Node.js** | JavaScript runtime | 20+ | `node script.js`, `npm install` |
| **Visual Studio Code** | Code editor | Latest | Open from Start Menu |
| **7-Zip** | File archiver | Latest | `7z x file.zip` |
| **Docker Desktop** | Container platform | Latest | `docker run`, `docker pull` |
| **VirtualBox** | Virtualization software | Latest | VM management |
| **Wireshark** | Network protocol analyzer | Latest | Packet capture |
| **Nmap** | Network scanner | Latest | `nmap target.com` |
| **Windows Terminal** | Modern terminal | Latest | Enhanced PowerShell |

---

## 🔄 Updating Tools

Regular updates ensure you have the latest features and security patches.

### Update Schedule Recommendation
- **Weekly**: Nuclei templates
- **Monthly**: Go tools, Python packages
- **Quarterly**: System dependencies (Chocolatey)
- **As Needed**: Wordlists

---

### Update Go Tools

**Update All Go Tools**:
```powershell
# Create update script
$goTools = @(
    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    "github.com/projectdiscovery/httpx/cmd/httpx@latest",
    "github.com/projectdiscovery/katana/cmd/katana@latest",
    "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
    "github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
    "github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest",
    "github.com/projectdiscovery/notify/cmd/notify@latest",
    "github.com/ffuf/ffuf/v2@latest",
    "github.com/OJ/gobuster/v3@latest",
    "github.com/owasp-amass/amass/v4/...@master",
    "github.com/tomnomnom/assetfinder@latest",
    "github.com/lc/gau/v2/cmd/gau@latest",
    "github.com/tomnomnom/waybackurls@latest",
    "github.com/hakluke/hakrawler@latest",
    "github.com/jaeles-project/gospider@latest",
    "github.com/tomnomnom/gf@latest",
    "github.com/tomnomnom/anew@latest",
    "github.com/tomnomnom/unfurl@latest",
    "github.com/tomnomnom/qsreplace@latest",
    "github.com/hahwul/dalfox/v2@latest",
    "github.com/Emoe/kxss@latest",
    "github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest",
    "github.com/gitleaks/gitleaks/v8@latest",
    "github.com/trufflesecurity/trufflehog/v3@latest"
)

foreach ($tool in $goTools) {
    Write-Host "Updating $tool..." -ForegroundColor Cyan
    go install $tool
}

Write-Host "`nAll Go tools updated!" -ForegroundColor Green
```

**Save as script and run**:
```powershell
# Save above code to: update-go-tools.ps1
# Then run:
.\update-go-tools.ps1
```

---

### Update Python Tools

**Update All Python Packages**:
```powershell
# Upgrade pip first
python -m pip install --upgrade pip

# Update all packages
python -m pip list --outdated

# Update specific security tools
python -m pip install --upgrade impacket crackmapexec bloodhound mitm6 responder arjun xsstrike sublist3r shodan censys

# Or update everything (may break dependencies)
python -m pip list --outdated --format=json | ConvertFrom-Json | ForEach-Object { python -m pip install --upgrade $_.name }
```

---

### Update Nuclei Templates

**Weekly Update** (Recommended):
```powershell
# Update templates
nuclei -update-templates

# Verify update
nuclei -version
nuclei -templates-version

# Count templates
nuclei -tl | Measure-Object -Line
```

**Check for New Templates**:
```powershell
# List recently added templates
nuclei -tl | Select-String -Pattern "$(Get-Date -Format 'yyyy-MM')"
```

---

### Update Chocolatey Packages

**Update All Packages**:
```powershell
# Update Chocolatey itself
choco upgrade chocolatey -y

# List outdated packages
choco outdated

# Update all packages
choco upgrade all -y

# Update specific package
choco upgrade git -y
choco upgrade python -y
choco upgrade golang -y
```

---

### Update Wordlists

**Update SecLists**:
```powershell
# Navigate to SecLists directory
cd $env:USERPROFILE\security-tools\wordlists\SecLists

# Pull latest changes
git pull

# Check what changed
git log --oneline -10
```

**Update PayloadsAllTheThings**:
```powershell
# Navigate to PayloadsAllTheThings directory
cd $env:USERPROFILE\security-tools\wordlists\PayloadsAllTheThings

# Pull latest changes
git pull

# Check what changed
git log --oneline -10
```

---

### Update Android Tools

**Update Android Studio**:
```powershell
# Launch Android Studio
# Help → Check for Updates
# Follow prompts to update
```

**Update Android SDK**:
```powershell
# In Android Studio:
# Tools → SDK Manager
# Check for updates in:
#   - SDK Platforms tab
#   - SDK Tools tab
# Click "Apply" to update
```

**Update ADB/Platform Tools**:
```powershell
# Download latest platform-tools
$url = "https://dl.google.com/android/repository/platform-tools-latest-windows.zip"
$output = "$env:USERPROFILE\Downloads\platform-tools-latest.zip"

Invoke-WebRequest -Uri $url -OutFile $output

# Backup old version
Rename-Item "$env:USERPROFILE\security-tools\platform-tools" "$env:USERPROFILE\security-tools\platform-tools-backup"

# Extract new version
Expand-Archive -Path $output -DestinationPath "$env:USERPROFILE\security-tools\" -Force

# Verify
adb version
```

---

### Update Docker Images

**Update MobSF**:
```powershell
# Pull latest image
docker pull opensecurity/mobile-security-framework-mobsf:latest

# Remove old containers
docker ps -a | Select-String "mobsf" | ForEach-Object { docker rm $_.Line.Split()[0] }

# Remove old images
docker images | Select-String "mobsf" | ForEach-Object { $id = $_.Line.Split()[2]; docker rmi $id }

# Run new version
docker run -it -p 8000:8000 opensecurity/mobile-security-framework-mobsf
```

---

### Update Burp Suite

**Check for Updates**:
```powershell
# Launch Burp Suite
# Burp → Check for updates
# Follow prompts to download and install
```

**Manual Update**:
```powershell
# Download latest version
$url = "https://portswigger.net/burp/releases/download?product=community&type=WindowsX64"
$output = "$env:USERPROFILE\security-tools\burpsuite_community_windows-x64-latest.exe"

Invoke-WebRequest -Uri $url -OutFile $output

# Run installer
Start-Process $output
```

---

### Automated Update Script

**Create Master Update Script**:
```powershell
# update-all-tools.ps1

Write-Host "==================================" -ForegroundColor Cyan
Write-Host "  Security Tools Update Script" -ForegroundColor Cyan
Write-Host "==================================" -ForegroundColor Cyan
Write-Host ""

# Update Chocolatey packages
Write-Host "[1/5] Updating Chocolatey packages..." -ForegroundColor Yellow
choco upgrade all -y

# Update Python packages
Write-Host "`n[2/5] Updating Python packages..." -ForegroundColor Yellow
python -m pip install --upgrade pip
python -m pip install --upgrade impacket crackmapexec arjun xsstrike sublist3r

# Update Go tools
Write-Host "`n[3/5] Updating Go tools..." -ForegroundColor Yellow
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/ffuf/ffuf/v2@latest
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
# Add more tools as needed

# Update Nuclei templates
Write-Host "`n[4/5] Updating Nuclei templates..." -ForegroundColor Yellow
nuclei -update-templates

# Update wordlists
Write-Host "`n[5/5] Updating wordlists..." -ForegroundColor Yellow
cd $env:USERPROFILE\security-tools\wordlists\SecLists
git pull
cd $env:USERPROFILE\security-tools\wordlists\PayloadsAllTheThings
git pull

Write-Host "`n==================================" -ForegroundColor Green
Write-Host "  All tools updated successfully!" -ForegroundColor Green
Write-Host "==================================" -ForegroundColor Green
```

**Run Update Script**:
```powershell
# Save as update-all-tools.ps1
# Then run monthly:
.\update-all-tools.ps1
```

---

## 🗑️ Uninstallation

Complete removal of all installed tools.

### Quick Uninstall

**Remove Everything**:
```powershell
# Remove main installation directory
Remove-Item -Recurse -Force "$env:USERPROFILE\security-tools"

# Remove Go tools
Remove-Item -Recurse -Force "$env:USERPROFILE\go"

# Remove bug bounty directory
Remove-Item -Recurse -Force "$env:USERPROFILE\bug-bounty"

# Uninstall Chocolatey packages
choco uninstall git python golang nodejs vscode 7zip docker-desktop virtualbox wireshark nmap sysinternals processhacker x64dbg zap -y

# Clean PATH
# See detailed instructions below
```

---

### Detailed Uninstallation Steps

#### Step 1: Remove Installation Directories
```powershell
# Remove security tools
if (Test-Path "$env:USERPROFILE\security-tools") {
    Write-Host "Removing security-tools directory..." -ForegroundColor Yellow
    Remove-Item -Recurse -Force "$env:USERPROFILE\security-tools"
}

# Remove Go installation
if (Test-Path "$env:USERPROFILE\go") {
    Write-Host "Removing Go directory..." -ForegroundColor Yellow
    Remove-Item -Recurse -Force "$env:USERPROFILE\go"
}

# Remove bug bounty workspace
if (Test-Path "$env:USERPROFILE\bug-bounty") {
    Write-Host "Removing bug-bounty directory..." -ForegroundColor Yellow
    Remove-Item -Recurse -Force "$env:USERPROFILE\bug-bounty"
}

# Remove Nuclei templates
if (Test-Path "$env:USERPROFILE\nuclei-templates") {
    Write-Host "Removing nuclei-templates..." -ForegroundColor Yellow
    Remove-Item -Recurse -Force "$env:USERPROFILE\nuclei-templates"
}

Write-Host "Directories removed successfully!" -ForegroundColor Green
```

---

#### Step 2: Uninstall Chocolatey Packages
```powershell
# List installed packages
choco list --local-only

# Uninstall core dependencies
choco uninstall git -y
choco uninstall python -y
choco uninstall python3 -y
choco uninstall golang -y
choco uninstall nodejs -y
choco uninstall vscode -y
choco uninstall 7zip -y
choco uninstall wget -y
choco uninstall curl -y
choco uninstall jq -y

# Uninstall security tools
choco uninstall sysinternals -y
choco uninstall processhacker -y
choco uninstall x64dbg.portable -y
choco uninstall ilspy -y
choco uninstall zap -y

# Uninstall virtualization
choco uninstall docker-desktop -y
choco uninstall virtualbox -y

# Uninstall network tools
choco uninstall wireshark -y
choco uninstall nmap -y

# Uninstall development tools
choco uninstall dotnet-sdk -y
choco uninstall dotnetcore-sdk -y
choco uninstall visualstudio2022buildtools -y
choco uninstall windows-sdk-10 -y
choco uninstall microsoft-windows-terminal -y
```

---

#### Step 3: Clean PATH Environment Variable
```powershell
# Get current User PATH
$currentPath = [Environment]::GetEnvironmentVariable("Path", "User")

# Split into array
$pathArray = $currentPath -split ";"

# Remove tool paths
$cleanedArray = $pathArray | Where-Object {
    $_ -notlike "*go\bin*" -and
    $_ -notlike "*security-tools*" -and
    $_ -notlike "*platform-tools*" -and
    $_ -notlike "*chocolatey*" -and
    $_ -notlike "*Python*" -and
    $_ -notlike "*nodejs*" -and
    $_ -ne ""
}

# Join back together
$cleanedPath = $cleanedArray -join ";"

# Set cleaned PATH
[Environment]::SetEnvironmentVariable("Path", $cleanedPath, "User")

Write-Host "PATH cleaned successfully!" -ForegroundColor Green
```

---

#### Step 4: Remove Python Packages
```powershell
# List installed packages
python -m pip list

# Uninstall security packages
python -m pip uninstall -y impacket crackmapexec bloodhound mitm6 responder pywerview ldapdomaindump kerbrute arjun xsstrike sublist3r playwright shodan censys securitytrails prowler scoutsuite

# Or uninstall all packages
python -m pip freeze | ForEach-Object { python -m pip uninstall -y $_ }
```

---

#### Step 5: Remove Docker Images
```powershell
# List images
docker images

# Remove MobSF
docker rmi opensecurity/mobile-security-framework-mobsf

# Remove all images
docker rmi $(docker images -q)

# Remove all containers
docker rm $(docker ps -a -q)

# Prune system
docker system prune -a --volumes -f
```

---

#### Step 6: Uninstall Chocolatey (Optional)
```powershell
# Remove Chocolatey directory
Remove-Item -Recurse -Force "C:\ProgramData\chocolatey"

# Remove from PATH
$currentPath = [Environment]::GetEnvironmentVariable("Path", "Machine")
$cleanedPath = ($currentPath -split ";") | Where-Object { $_ -notlike "*chocolatey*" } | Join-Object -Separator ";"
[Environment]::SetEnvironmentVariable("Path", $cleanedPath, "Machine")
```

---

#### Step 7: Remove Log Files
```powershell
# Remove installation log
if (Test-Path "$env:USERPROFILE\security-tools-install.log") {
    Remove-Item "$env:USERPROFILE\security-tools-install.log"
}

# Remove other logs
Remove-Item "$env:TEMP\chocolatey\*" -Recurse -Force -ErrorAction SilentlyContinue
```

---

#### Step 8: Clean Registry (Advanced)
```powershell
# Remove Go registry entries
Remove-Item -Path "HKCU:\Environment" -Name "GOPATH" -ErrorAction SilentlyContinue
Remove-Item -Path "HKCU:\Environment" -Name "GOROOT" -ErrorAction SilentlyContinue

# Remove Android SDK registry entries
Remove-Item -Path "HKCU:\Environment" -Name "ANDROID_SDK_ROOT" -ErrorAction SilentlyContinue
Remove-Item -Path "HKCU:\Environment" -Name "ANDROID_HOME" -ErrorAction SilentlyContinue
```

---

#### Step 9: Restart Computer
```powershell
# Restart to complete uninstallation
Write-Host "`nUninstallation complete!" -ForegroundColor Green
Write-Host "Please restart your computer to finalize changes." -ForegroundColor Yellow

# Restart now?
$restart = Read-Host "Restart now? (Y/N)"
if ($restart -eq "Y" -or $restart -eq "y") {
    shutdown /r /t 30 /c "Restarting to complete uninstallation..."
}
```

---

### Complete Uninstall Script

**Save as: uninstall-security-tools.ps1**
```powershell
#Requires -RunAsAdministrator

Write-Host "==========================================" -ForegroundColor Red
Write-Host "  Security Tools - Complete Uninstaller" -ForegroundColor Red
Write-Host "==========================================" -ForegroundColor Red
Write-Host ""
Write-Warning "This will remove ALL security tools and dependencies!"
Write-Host ""

$confirm = Read-Host "Are you sure you want to continue? (yes/no)"

if ($confirm -ne "yes") {
    Write-Host "Uninstallation cancelled." -ForegroundColor Yellow
    exit
}

Write-Host "`nStarting uninstallation..." -ForegroundColor Yellow

# Remove directories
Write-Host "`n[1/7] Removing installation directories..." -ForegroundColor Cyan
Remove-Item -Recurse -Force "$env:USERPROFILE\security-tools" -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force "$env:USERPROFILE\go" -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force "$env:USERPROFILE\bug-bounty" -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force "$env:USERPROFILE\nuclei-templates" -ErrorAction SilentlyContinue

# Uninstall Chocolatey packages
Write-Host "`n[2/7] Uninstalling Chocolatey packages..." -ForegroundColor Cyan
$packages = @("git", "python", "golang", "nodejs", "vscode", "docker-desktop", "virtualbox", "wireshark", "nmap", "sysinternals", "processhacker", "x64dbg.portable", "ilspy", "zap")
foreach ($pkg in $packages) {
    choco uninstall $pkg -y --remove-dependencies
}

# Clean PATH
Write-Host "`n[3/7] Cleaning PATH environment variable..." -ForegroundColor Cyan
$currentPath = [Environment]::GetEnvironmentVariable("Path", "User")
$cleanedPath = ($currentPath -split ";") | Where-Object {
    $_ -notlike "*go\bin*" -and
    $_ -notlike "*security-tools*" -and
    $_ -notlike "*chocolatey*" -and
    $_ -ne ""
} | Join-Object -Separator ";"
[Environment]::SetEnvironmentVariable("Path", $cleanedPath, "User")

# Remove Docker images
Write-Host "`n[4/7] Removing Docker images..." -ForegroundColor Cyan
docker rmi opensecurity/mobile-security-framework-mobsf -f 2>$null
docker system prune -a --volumes -f 2>$null

# Remove Python packages
Write-Host "`n[5/7] Removing Python packages..." -ForegroundColor Cyan
python -m pip uninstall -y impacket crackmapexec arjun xsstrike sublist3r 2>$null

# Remove logs
Write-Host "`n[6/7] Removing log files..." -ForegroundColor Cyan
Remove-Item "$env:USERPROFILE\security-tools-install.log" -ErrorAction SilentlyContinue
Remove-Item "$env:TEMP\chocolatey\*" -Recurse -Force -ErrorAction SilentlyContinue

# Clean registry
Write-Host "`n[7/7] Cleaning registry..." -ForegroundColor Cyan
Remove-Item -Path "HKCU:\Environment" -Name "GOPATH" -ErrorAction SilentlyContinue
Remove-Item -Path "HKCU:\Environment" -Name "ANDROID_SDK_ROOT" -ErrorAction SilentlyContinue

Write-Host "`n==========================================" -ForegroundColor Green
Write-Host "  Uninstallation completed successfully!" -ForegroundColor Green
Write-Host "==========================================" -ForegroundColor Green
Write-Host ""
Write-Host "Please restart your computer to finalize changes." -ForegroundColor Yellow
```

**Run Uninstall Script**:
```powershell
# Run as Administrator
.\uninstall-security-tools.ps1
```

---

## 🔒 Security Considerations

### Antivirus and Windows Defender

Many security tools contain exploit code or perform system manipulation that antivirus software flags as malicious. This is expected and normal behavior for legitimate security testing tools.

**Why Tools Are Flagged**:
- Tools contain exploit code (e.g., Metasploit payloads, XSS scripts)
- Tools perform network scanning (e.g., Nmap, Masscan)
- Tools manipulate system processes (e.g., Process Hacker, x64dbg)
- Tools use obfuscation techniques (common in Android tools)

**Recommendations**:

1. **Add Exclusions Before Installation**:
   ```powershell
   # Windows Defender exclusions
   Add-MpPreference -ExclusionPath "$env:USERPROFILE\security-tools"
   Add-MpPreference -ExclusionPath "$env:USERPROFILE\go\bin"
   Add-MpPreference -ExclusionPath "C:\ProgramData\chocolatey"
   ```

2. **Download from Official Sources Only**:
   - ✅ GitHub official repositories
   - ✅ Official project websites
   - ✅ Chocolatey verified packages
   - ❌ Third-party mirrors
   - ❌ Unofficial downloads

3. **Verify File Hashes** (when available):
   ```powershell
   # Get file hash
   Get-FileHash -Path "tool.exe" -Algorithm SHA256
   
   # Compare with official hash from project website
   ```

4. **Run in Isolated Environment**:
   - Use virtual machine for testing unknown tools
   - Use separate test network for scanning activities
   - Don't use primary workstation for exploit testing

---

### Network Security

Some tools generate significant network traffic and may trigger IDS/IPS alerts.

**Tools That Generate High Traffic**:
- **Port Scanners**: Nmap, Masscan, Naabu
- **Web Crawlers**: Katana, Gospider, Hakrawler
- **Vulnerability Scanners**: Nuclei, OWASP ZAP
- **Fuzzing Tools**: Ffuf, Gobuster

**Best Practices**:

1. **Only Scan Authorized Targets**:
   ```powershell
   # Always get written permission before scanning
   # Unauthorized scanning is illegal in most jurisdictions
   ```

2. **Use VPN or Proxy When Appropriate**:
   ```powershell
   # Configure proxy in tools
   export HTTP_PROXY=http://proxy.example.com:8080
   export HTTPS_PROXY=https://proxy.example.com:8080
   ```

3. **Respect Rate Limits**:
   ```powershell
   # Use rate limiting in tools
   nuclei -rate-limit 50  # 50 requests per second
   ffuf -rate 100         # 100 requests per second
   ```

4. **Follow robots.txt**:
   ```powershell
   # Check robots.txt before crawling
   curl https://example.com/robots.txt
   ```

5. **Use Responsible Disclosure**:
   - Report vulnerabilities to security teams
   - Give time to fix before public disclosure
   - Follow coordinated disclosure practices

---

### Legal Considerations

⚠️ **WARNING: Unauthorized security testing is illegal**

**You Must Have Authorization**:
- Written permission from target owner
- Signed contract for penetration testing
- Participation in authorized bug bounty program
- Testing on your own systems/applications

**Legal Frameworks**:
- **USA**: Computer Fraud and Abuse Act (CFAA)
- **EU**: Computer Misuse Act, GDPR
- **International**: Varies by country

**Safe Testing Environments**:
- Your own lab/servers
- Bug bounty programs (HackerOne, Bugcrowd, Intigriti)
- Authorized penetration testing engagements
- Vulnerability disclosure programs
- CTF competitions
- Practice platforms (HackTheBox, TryHackMe)

**Never Test Without Permission**:
- ❌ Employer's systems (without explicit authorization)
- ❌ Educational institutions
- ❌ Government systems
- ❌ Public websites/services
- ❌ Third-party applications

---

### Privacy Considerations

**Data Collection**:
- Some tools send telemetry (check privacy policies)
- API-based tools (Shodan, Censys) log requests
- Cloud-based tools may store scan data

**Minimize Data Exposure**:
```powershell
# Disable telemetry when available
nuclei -disable-update-check

# Use local tools when possible
# Avoid cloud-based scanners for sensitive targets

# Encrypt results
# Store results in encrypted containers
```

**GDPR Compliance** (if in EU):
- Don't scan systems containing personal data without authorization
- Follow data minimization principles
- Implement data retention policies

---

### Secure Usage Practices

1. **Keep Tools Updated**:
   ```powershell
   # Weekly updates for active tools
   nuclei -update-templates
   go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
   ```

2. **Use Strong Authentication**:
   - Enable 2FA on all accounts (GitHub, bug bounty platforms)
   - Use password manager for credentials
   - Don't store credentials in scripts

3. **Secure Your Workspace**:
   ```powershell
   # Encrypt sensitive directories
   # Use BitLocker or VeraCrypt
   
   # Set file permissions
   icacls "$env:USERPROFILE\security-tools" /inheritance:r
   icacls "$env:USERPROFILE\security-tools" /grant:r "$env:USERNAME:(OI)(CI)F"
   ```

4. **Secure Communication**:
   - Use VPN for security research
   - Use encrypted messaging for reporting
   - Use PGP for sensitive communications

5. **Clean Up After Testing**:
   ```powershell
   # Remove test payloads
   # Clear logs
   # Delete sensitive results
   
   Remove-Item "$env:USERPROFILE\bug-bounty\results\*" -Recurse -Force
   ```

---

### Responsible Disclosure

When you find vulnerabilities:

1. **Contact Security Team**:
   - Look for security.txt: `https://example.com/.well-known/security.txt`
   - Check for bug bounty program
   - Email: security@example.com

2. **Provide Details**:
   - Vulnerability description
   - Steps to reproduce
   - Impact assessment
   - Suggested remediation

3. **Give Time to Fix**:
   - Typically 90 days before public disclosure
   - Coordinate disclosure timeline
   - Respect fix verification process

4. **Follow Program Rules**:
   - Read scope carefully
   - Respect out-of-scope items
   - Don't test in production if prohibited
   - Follow reporting guidelines

---

## ❓ FAQ

### General Questions

**Q: How long does installation take?**
A: 40-70 minutes depending on internet speed. Faster connections complete in 40 minutes, slower connections may take up to 70 minutes.

**Q: Can I install only specific tools?**
A: Yes, modify the script to comment out unwanted installations. Add `#` before lines you want to skip.

**Q: Will this slow down my computer?**
A: Tools don't run in background. Performance impact only when actively using tools. Docker Desktop uses ~2GB RAM when running.

**Q: Can I install on Windows 10?**
A: Yes, fully compatible with Windows 10 (64-bit) version 1909 or higher.

**Q: Do I need administrator rights?**
A: Yes, administrator rights required for Chocolatey and system-wide tool installation.

---

### Technical Questions

**Q: Why are some tools flagged as malware?**
A: Security tools contain exploit code that antivirus software flags. This is expected. Add exclusions or temporarily disable antivirus during installation.

**Q: Can I use these tools on my work computer?**
A: Check with your IT department first. Many organizations prohibit security tools on corporate networks.

**Q: What's the difference between this and Kali Linux?**
A: This provides similar tools for Windows. Kali Linux is a dedicated security distribution. Use Kali in VM, these tools for native Windows testing.

**Q: Do I need to update tools regularly?**
A: Yes. Update Nuclei templates weekly, Go/Python tools monthly, and system dependencies quarterly.

**Q: Can I contribute to improve this script?**
A: Yes! Submit pull requests on GitHub with improvements or additional tools.

---

### Troubleshooting Questions

**Q: Script fails with "Access Denied" error?**
A: Run PowerShell as Administrator. Right-click PowerShell → "Run as Administrator"

**Q: Chocolatey installation fails?**
A: Check internet connection. Verify .NET Framework 4.8+ installed. Try manual Chocolatey installation.

**Q: Go tools not found after installation?**
A: Restart PowerShell to refresh PATH. Or manually add `%USERPROFILE%\go\bin` to PATH.

**Q: ADB doesn't recognize my device?**
A: Enable USB debugging on Android device. Install device-specific USB drivers. Try different USB cable/port.

**Q: Docker Desktop won't start?**
A: Enable WSL2 or Hyper-V. Restart computer. Check BIOS virtualization settings (VT-x/AMD-V).

. Try installing failed tool manually. Check internet connectivity.

---

### Usage Questions

**Q: Which tools should I learn first?**
A: Start with: Subfinder (subdomain enum), Httpx (probing), Nuclei (scanning), Burp Suite (manual testing).

**Q: Are these tools legal to use?**
A: Tools are legal to own and use on authorized targets. Unauthorized use is illegal. Only test systems you have permission to test.

**Q: Can I use these for bug bounties?**
A: Yes! These tools are commonly used in bug bounty hunting. Follow program rules and scope.

**Q: How do I report bugs found with these tools?**
A: Follow responsible disclosure. Contact security team, provide details, give time to fix before public disclosure.

**Q: Where can I practice using these tools?**
A: Legal practice environments: HackTheBox, TryHackMe, PentesterLab, your own lab, authorized bug bounty programs.

---

### Advanced Questions

**Q: Can I modify the script to add custom tools?**
A: Yes! Add tools to appropriate sections (Go tools, Python tools, etc.). Follow existing pattern.

**Q: How do I integrate these tools into my workflow?**
A: Create bash/PowerShell scripts to chain tools together. Example: `subfinder | httpx | nuclei`

**Q: Can I use these tools for commercial penetration testing?**
A: Yes, but verify tool licenses. Some tools require commercial licenses for commercial use.

**Q: How do I contribute new templates to Nuclei?**
A: Fork nuclei-templates repository on GitHub, create new template, submit pull request.

**Q: Can I automate scanning with these tools?**
A: Yes! Create scheduled tasks in Windows or use automation tools like Jenkins, GitHub Actions.

---

## 📞 Support & Resources

### Official Documentation

**ProjectDiscovery Tools**:
- Nuclei: https://docs.projectdiscovery.io/nuclei/
- Subfinder: https://docs.projectdiscovery.io/tools/subfinder/
- Httpx: https://docs.projectdiscovery.io/tools/httpx/
- Katana: https://docs.projectdiscovery.io/tools/katana/

**Tool Documentation**:
- Burp Suite: https://portswigger.net/burp/documentation
- OWASP ZAP: https://www.zaproxy.org/docs/
- Ffuf: https://github.com/ffuf/ffuf
- Amass: https://github.com/owasp-amass/amass/blob/master/doc/user_guide.md

**Android Tools**:
- ADB: https://developer.android.com/studio/command-line/adb
- JADX: https://github.com/skylot/jadx
- APKTool: https://ibotpeaches.github.io/Apktool/
- MobSF: https://mobsf.github.io/docs/

---

### Community Resources

**Discord Servers**:
- ProjectDiscovery: https://discord.gg/projectdiscovery
- Bug Bounty Hunters: Various servers for platforms

**Forums**:
- Reddit: r/netsec, r/AskNetsec, r/bugbounty
- Stack Overflow: Security tag

**Learning Platforms**:
- HackTheBox: https://www.hackthebox.com
- TryHackMe: https://tryhackme.com
- PentesterLab: https://pentesterlab.com
- PortSwigger Web Security Academy: https://portswigger.net/web-security

---

### Bug Bounty Platforms

- **HackerOne**: https://www.hackerone.com
- **Bugcrowd**: https://www.bugcrowd.com
- **Intigriti**: https://www.intigriti.com
- **YesWeHack**: https://www.yeswehack.com
- **Synack**: https://www.synack.com

---

### Getting Help

**Script Issues**:
- Check log file: `$env:USERPROFILE\security-tools-install.log`
- Review troubleshooting section
- Search existing GitHub issues
- Create new GitHub issue with log file

**Tool-Specific Issues**:
- Check tool's official documentation
- Search tool's GitHub issues
- Ask in tool's Discord/forum
- Create issue on tool's repository

**General Security Questions**:
- r/AskNetsec on Reddit
- Information Security Stack Exchange
- Security-focused Discord servers

---

### Additional Resources

**Security Research Blogs**:
- PortSwigger Research: https://portswigger.net/research
- ProjectDiscovery Blog: https://blog.projectdiscovery.io
- Google Project Zero: https://googleprojectzero.blogspot.com

**Bug Bounty Writeups**:
- HackerOne Hacktivity: https://hackerone.com/hacktivity
- Pentester Land: https://pentester.land
- Medium Bug Bounty tag

**Video Tutorials**:
- YouTube: Search for specific tools
- Udemy/Coursera: Security courses
- PentesterAcademy: Video courses

---

## 📄 License & Legal

### Tools Licenses

Different tools have different licenses. Most are open source:

- **MIT License**: Nuclei, Subfinder, Httpx, many others
- **GPL**: OWASP ZAP, some Sysinternals tools
- **Apache 2.0**: Amass, some Go tools
- **Commercial**: Burp Suite Pro (Community version is free)

**Check individual tool licenses before commercial use**.

---

### Script License

This installation script is provided "as is" without warranty.

**Usage Terms**:
- ✅ Personal use
- ✅ Educational use
- ✅ Commercial use (script itself, not necessarily all tools)
- ✅ Modification and redistribution

**Disclaimer**:
```
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

### Legal Disclaimer

⚠️ **IMPORTANT LEGAL NOTICE**

This tool collection is intended for:
- Authorized security testing
- Educational purposes
- Security research
- Bug bounty programs
- Penetration testing with written permission

**Unauthorized use of these tools is illegal and may result in:**
- Criminal prosecution
- Civil liability
- Termination of employment
- Termination from educational institutions
- Blacklisting from bug bounty programs

**Users are responsible for:**
- Obtaining proper authorization before testing
- Following all applicable laws and regulations
- Respecting privacy and data protection laws
- Following responsible disclosure practices
- Understanding and accepting risks

**By using this script and tools, you agree to:**
- Use tools only on authorized targets
- Follow all applicable laws
- Accept full responsibility for your actions
- Not hold script author liable for misuse

---

## 🎉 Conclusion

You now have a comprehensive Windows security testing toolkit installed and ready to use.

### What You've Installed

✅ **60+ security tools** covering:
- Subdomain enumeration
- Web application testing
- Vulnerability scanning
- Android security
- Windows binary analysis
- Reverse engineering
- Network analysis
- Active Directory testing

✅ **Development environment** with:
- Python 3.11+
- Go 1.21+
- Node.js 20+
- Git, Docker, VirtualBox

✅ **Wordlists** with:
- 40,000+ SecLists files
- 1,000+ PayloadsAllTheThings

---

### Next Steps

1. **Familiarize yourself with tools**:
   - Start with basic tools (Subfinder, Httpx, Nuclei)
   - Practice on authorized targets
   - Follow tool documentation

2. **Join bug bounty platforms**:
   - Create accounts on HackerOne, Bugcrowd
   - Read program scopes carefully
   - Start with easy targets

3. **Practice safely**:
   - Use HackTheBox, TryHackMe
   - Set up home lab
   - Follow responsible disclosure

4. **Stay updated**:
   - Update Nuclei templates weekly
   - Update tools monthly
   - Follow security researchers on Twitter

5. **Learn continuously**:
   - Read writeups and blogs
   - Watch tutorials and courses
   - Participate in CTFs
   - Join security communities

---

### Stay Secure, Stay Legal, Happy Hunting! 🎯

Remember: With great tools comes great responsibility. Always get permission before testing!

---

**Version**: 1.0.0  
**Last Updated**: 2024  
**Maintained By**: Security Tools Community

---

*This README is for the Windows PowerShell installation script. For Linux installation, see the Linux README.*
```

**Q: Installation hangs at specific tool?**
A: Check log file for errors

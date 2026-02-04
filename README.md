# ArcReactor.ps1 - Windows Security Tools Automated Installer

```
╔═══════════════════════════════════════════════════════════════════╗
║                                                                   ║
║                    ⚡ ARC REACTOR ⚡                              ║
║              Windows Security Tools Installer                     ║
║                                                                   ║
║        Automated Installation of 25+ Security Tools              ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝
```

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1+-blue.svg)](https://github.com/PowerShell/PowerShell)
[![Platform](https://img.shields.io/badge/Platform-Windows%2010%2F11-lightgrey.svg)](https://www.microsoft.com/windows)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**One script to rule them all** - Automated installation of essential security and bug bounty tools for Windows.

[Installation](#-installation-instructions) • [Tools](#-complete-tool-list) • [Usage](#-tool-usage-examples) • [Troubleshooting](#-troubleshooting)

---

## 📋 Overview

**ArcReactor.ps1** is a comprehensive PowerShell script that automates the installation of security testing, bug bounty hunting, and mobile application security tools on Windows systems. Instead of manually installing dozens of tools, ArcReactor does it all in one run.

### ✨ Key Features

- 🚀 **One-Click Installation**: Install 25+ tools with a single command
- 🔧 **Automatic Configuration**: Sets up PATH, downloads dependencies, configures tools
- 📦 **Package Management**: Uses Chocolatey for system packages
- 🎯 **Curated Tool List**: Only essential, proven security tools
- 📝 **Comprehensive Logging**: Track installation progress and errors
- 🔄 **Update Support**: Easy tool updates via helper scripts

### 🎯 Use Cases

- **Bug Bounty Hunting**: Web reconnaissance, vulnerability scanning, subdomain enumeration
- **Penetration Testing**: Network scanning, web application testing
- **Mobile Security**: Android app analysis, dynamic instrumentation with Frida
- **Security Research**: API reconnaissance, certificate transparency analysis

---

## 💻 System Requirements

| Requirement | Minimum | Recommended |
|------------|---------|-------------|
| **Operating System** | Windows 10 (64-bit) | Windows 11 (64-bit) |
| **PowerShell** | 5.1 | 7.x |
| **RAM** | 8GB | 16GB |
| **Disk Space** | 20GB free | 50GB free |
| **Internet** | Stable connection | High-speed connection |
| **Privileges** | Administrator | Administrator |

### 📌 Software Prerequisites

- Windows 10 version 1909 or higher (or Windows 11)
- PowerShell 5.1 or higher
- .NET Framework 4.8 or higher
- Active internet connection
- Administrator access

### ⚠️ Important Notes

- **Admin Rights Required**: Must run as Administrator
- **Antivirus**: Temporarily disable or add exclusions for security tools
- **VPN**: Disable during installation (can cause timeouts)
- **Time**: Allow 40-70 minutes for complete installation


## 📚 Complete Tool List

### System Dependencies (12)
| Tool | Description | Use Case |
|------|-------------|----------|
| Git | Version control | Clone repositories |
| Python 3 | Programming language | Python scripts |
| Go | Programming language | Go-based tools |
| Node.js | JavaScript runtime | Node-based tools |
| 7-Zip | Archive utility | Extract compressed files |
| wget/curl | Download utilities | Fetch files |
| Nmap | Network scanner | Port scanning |
| Wireshark | Packet analyzer | Network analysis |
| Docker Desktop | Container platform | Run containerized tools |
| OpenJDK | Java runtime | Java-based tools |
| Chocolatey | Package manager | Windows package management |

### Go Security Tools (9)
| Tool | Description | GitHub Stars | Primary Use |
|------|-------------|--------------|-------------|
| Nuclei | Vulnerability scanner | 17k+ | Automated vuln detection |
| Subfinder | Subdomain discovery | 8k+ | Passive subdomain enum |
| Httpx | HTTP toolkit | 6k+ | Probing live hosts |
| Katana | Web crawler | 7k+ | Modern web crawling |
| Naabu | Port scanner | 4k+ | Fast port scanning |
| Dnsx | DNS toolkit | 1k+ | DNS queries/validation |
| Notify | Notifications | 1k+ | Multi-channel alerts |
| Ffuf | Web fuzzer | 11k+ | Directory/param fuzzing |
| Gobuster | Brute-forcer | 9k+ | Directory/DNS enum |

### Python Security Tools (7)
| Tool | Description | Use Case |
|------|-------------|----------|
| requests | HTTP library | HTTP requests |
| beautifulsoup4 | HTML parser | Web scraping |
| dnspython | DNS toolkit | DNS operations |
| censys | Censys API | Certificate/host search |
| shodan | Shodan API | Internet-wide scanning |
| securitytrails | SecurityTrails API | DNS intelligence |
| frida-tools | Dynamic instrumentation | Runtime app analysis |

### Web Application Security (2)
| Tool | Description | License |
|------|-------------|---------|
| Burp Suite Community | Web proxy/scanner | Free |
| OWASP ZAP | Automated web scanner | Free |

### Android Security Tools (7)
| Tool | Description | Use Case |
|------|-------------|----------|
| ADB | Android Debug Bridge | Device communication |
| Fastboot | Android flashing | Device flashing |
| Android Studio | Official IDE | Android development |
| JADX | APK decompiler | Dex to Java |
| APKTool | APK reverse engineering | Decompile/rebuild APKs |
| Frida | Dynamic instrumentation | Runtime hooking |
| MobSF | Mobile security framework | Comprehensive app analysis |

### Wordlists (1)
| Collection | Files | Size | Categories |
|------------|-------|------|------------|
| SecLists | 40,000+ | ~1GB | Discovery, Passwords, Fuzzing, Payloads |

**Total Tools: 25+ security tools**

---

## 📖 Additional Resources

### Official Documentation
- **Nuclei**: https://docs.projectdiscovery.io/nuclei/
- **Subfinder**: https://docs.projectdiscovery.io/tools/subfinder/
- **Burp Suite**: https://portswigger.net/burp/documentation
- **Frida**: https://frida.re/docs/home/
- **JADX**: https://github.com/skylot/jadx

### Learning Platforms
---

## ✅ Pre-Installation Checklist

### 1. System Preparation

- [ ] **Backup important data** - Always backup before major installations
- [ ] **Check disk space** - Ensure at least 20GB free on C: drive
- [ ] **Close applications** - Close all running programs
- [ ] **Windows updates** - Install pending Windows updates

### 2. Antivirus Configuration

Many security tools will be flagged as malicious (expected behavior). Choose one:

**Option A - Temporarily Disable** (Recommended):
- Right-click antivirus icon → Disable protection for 1-2 hours

**Option B - Add Exclusions**:
```
C:\Users\YourUsername\security-tools\
C:\Users\YourUsername\go\bin\
C:\ProgramData\chocolatey\
```

### 3. Network Configuration

- [ ] Disable VPN during installation
- [ ] Ensure stable internet connection
- [ ] Check that proxy isn't blocking downloads

### 4. Verify PowerShell Version

```powershell
$PSVersionTable.PSVersion
# Should show 5.1 or higher
```

---

## 🚀 Installation Instructions

### Method 1: Standard Installation (Recommended)

#### Step 1: Download the Script

Download `ArcReactor.ps1` to your computer (e.g., Downloads folder)

#### Step 2: Open PowerShell as Administrator

1. Press `Windows + X`
2. Select **"Windows PowerShell (Admin)"** or **"Terminal (Admin)"**
3. Click **"Yes"** on UAC prompt

#### Step 3: Navigate to Script Location

```powershell
cd $env:USERPROFILE\Downloads
```

#### Step 4: Set Execution Policy

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
```

#### Step 5: Run ArcReactor

```powershell
.\ArcReactor.ps1
```

#### Step 6: Monitor Installation

- Watch colored output for progress
- Installation takes 40-70 minutes
- **Do NOT close PowerShell** during installation
- Script shows summary at the end

---

### Method 2: Quick One-Liner

```powershell
cd $env:USERPROFILE\Downloads; Set-ExecutionPolicy Bypass -Scope Process -Force; .\ArcReactor.ps1
```

---

### Method 3: Download and Run (Direct URL)

If script is hosted on GitHub:

```powershell
# Download
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/yourusername/arireactor/main/ArcReactor.ps1" -OutFile "$env:USERPROFILE\Downloads\ArcReactor.ps1"

# Run
cd $env:USERPROFILE\Downloads
Set-ExecutionPolicy Bypass -Scope Process -Force
.\ArcReactor.ps1
```

---

## 📦 What Gets Installed

### Installation Timeline

```
Phase 1: Chocolatey Package Manager      [▓▓░░░░░░░░] 2-3 min
Phase 2: System Dependencies             [▓▓▓▓░░░░░░] 5-10 min
Phase 3: Python Security Tools           [▓▓▓░░░░░░░] 3-5 min
Phase 4: Go Security Tools               [▓▓▓▓▓▓░░░░] 10-15 min
Phase 5: Web Application Tools           [▓▓▓▓░░░░░░] 5-10 min
Phase 6: Android Security Tools          [▓▓▓▓░░░░░░] 5-10 min
Phase 7: Wordlists                       [▓▓░░░░░░░░] 2-5 min
Phase 8: Configuration & Updates         [▓░░░░░░░░░] 1-2 min
                                         ───────────────────
                               Total Time: 40-70 minutes
```

### Detailed Installation Phases

#### Phase 1: Package Manager (2-3 min)
- ✅ Chocolatey (Windows package manager)

#### Phase 2: System Dependencies (5-10 min)
- ✅ Git (version control)
- ✅ Python 3.x (programming language)
- ✅ Go 1.21+ (Go compiler)
- ✅ Node.js (JavaScript runtime)
- ✅ 7-Zip (archive utility)
- ✅ wget, curl (download utilities)
- ✅ Nmap (network scanner)
- ✅ Wireshark (packet analyzer)
- ✅ Docker Desktop (container platform)
- ✅ OpenJDK (Java runtime)

#### Phase 3: Python Security Tools (3-5 min)
- ✅ requests (HTTP library)
- ✅ beautifulsoup4 (web scraping)
- ✅ dnspython (DNS toolkit)
- ✅ censys (Censys API client)
- ✅ shodan (Shodan API client)
- ✅ securitytrails (SecurityTrails API)
- ✅ frida-tools (dynamic instrumentation)

#### Phase 4: Go Security Tools (10-15 min)
- ✅ nuclei (vulnerability scanner - 3000+ templates)
- ✅ subfinder (subdomain enumeration)
- ✅ httpx (HTTP probing toolkit)
- ✅ katana (next-gen web crawler)
- ✅ naabu (fast port scanner)
- ✅ dnsx (DNS toolkit)
- ✅ notify (multi-channel notifications)
- ✅ ffuf (fast web fuzzer)
- ✅ gobuster (directory brute-forcer)

#### Phase 5: Web Application Security (5-10 min)
- ✅ Burp Suite Community (web proxy - download only)
- ✅ OWASP ZAP (automated web scanner)

#### Phase 6: Android Security Tools (5-10 min)
- ✅ ADB (Android Debug Bridge)
- ✅ Fastboot (Android flashing tool)
- ✅ Android Studio (full Android IDE)
- ✅ JADX (APK decompiler)
- ✅ APKTool (APK reverse engineering)
- ✅ Frida Server (for Android devices - all architectures)
- ✅ MobSF (Mobile Security Framework - Docker)

#### Phase 7: Wordlists (2-5 min)
- ✅ SecLists (40,000+ security testing wordlists)

#### Phase 8: Configuration (1-2 min)
- ✅ Nuclei template updates
- ✅ PATH environment configuration
- ✅ Directory structure creation

---

## 📁 Installation Locations

### Main Installation Directory
```
C:\Users\YourUsername\security-tools\
│
├── platform-tools\              # Android SDK Platform Tools
│   ├── adb.exe                  # Android Debug Bridge
│   ├── fastboot.exe             # Fastboot utility
│   └── [other Android tools]
│
├── jadx\                        # JADX APK Decompiler
│   ├── bin\
│   │   ├── jadx.bat             # CLI decompiler
│   │   └── jadx-gui.bat         # GUI version
│   └── lib\
│
├── apktool\                     # APKTool
│   ├── apktool.jar
│   └── apktool.bat
│
├── frida-server\                # Frida Server for Android
│   ├── frida-server-*-android-arm.xz
│   ├── frida-server-*-android-arm64.xz
│   ├── frida-server-*-android-x86.xz
│   └── frida-server-*-android-x86_64.xz
│
├── wordlists\                   # Security Wordlists
│   └── SecLists\
│       ├── Discovery\
│       │   ├── Web-Content\
│       │   └── DNS\
│       ├── Passwords\
│       ├── Usernames\
│       └── Fuzzing\
│
├── tools\                       # Additional tools
├── scripts\                     # Helper scripts
├── results\                     # Scan results
└── burpsuite_community_windows-x64.exe  # Burp installer
```

### Go Tools Location
```
C:\Users\YourUsername\go\bin\
├── nuclei.exe
├── subfinder.exe
├── httpx.exe
├── katana.exe
├── naabu.exe
├── dnsx.exe
├── notify.exe
├── ffuf.exe
└── gobuster.exe
```

### Python Packages Location
```
C:\Python311\Scripts\
├── frida.exe
├── frida-ps.exe
├── frida-trace.exe
└── [other frida tools]
```

### Bug Bounty Workspace
```
C:\Users\YourUsername\bug-bounty\
│
├── recon\                       # Reconnaissance results
├── scanning\                    # Vulnerability scans
├── exploitation\                # Exploitation POCs
└── reporting\                   # Reports and writeups
```

### Log File
```
C:\Users\YourUsername\security-tools-install.log
```

---

## ✨ Post-Installation Steps

### Step 1: Restart PowerShell

Close and reopen PowerShell to refresh PATH environment variables.

### Step 2: Verify Installation

```powershell
# Test Go tools
nuclei -version
subfinder -version
httpx -version
ffuf -V

# Test Python tools
python --version
frida --version

# Test Android tools
adb version

# Test PATH
$env:Path -split ";" | Select-String -Pattern "go\\bin"
```

**Expected Output**:
```
✓ Nuclei v3.x.x
✓ Subfinder v2.x.x
✓ Httpx v1.x.x
✓ Python 3.11.x
✓ Frida 16.x.x
✓ Android Debug Bridge version 1.0.41
```

### Step 3: Update Nuclei Templates

```powershell
nuclei -update-templates
```

### Step 4: Complete Burp Suite Installation

```powershell
cd $env:USERPROFILE\security-tools
.\burpsuite_community_windows-x64.exe
```

### Step 5: Setup Frida on Android Device

#### Enable USB Debugging on Android:
1. Settings → About Phone
2. Tap "Build Number" 7 times
3. Settings → Developer Options → Enable "USB Debugging"

#### Push Frida Server to Device:
```powershell
# Find your device architecture
adb shell getprop ro.product.cpu.abi
# Output example: arm64-v8a

# Extract Frida Server for your architecture
cd $env:USERPROFILE\security-tools\frida-server
# Use 7-Zip to extract the appropriate .xz file

# Push to device
adb push frida-server-*-android-arm64 /data/local/tmp/frida-server

# Make executable
adb shell "chmod 755 /data/local/tmp/frida-server"

# Run Frida Server (keep this terminal open)
adb shell "/data/local/tmp/frida-server &"

# Test from another terminal
frida-ps -U
```

### Step 6: Start Docker Desktop

For MobSF (Mobile Security Framework):
```powershell
# Start Docker Desktop from Start Menu

# Pull MobSF image
docker pull opensecurity/mobile-security-framework-mobsf

# Run MobSF
docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf

# Access: http://localhost:8000
```

---

## 🎓 Tool Usage Examples

### Subdomain Enumeration

```powershell
# Basic subdomain discovery
subfinder -d example.com -o subdomains.txt

# Comprehensive enumeration
subfinder -d example.com -all -recursive -o subdomains_all.txt
```

### Web Reconnaissance

```powershell
# Probe for live hosts
cat subdomains.txt | httpx -silent -o alive_hosts.txt

# Detailed HTTP probing
cat subdomains.txt | httpx -status-code -title -tech-detect -o detailed_info.txt

# Web crawling
katana -u https://example.com -o urls.txt
```

### Directory Fuzzing

```powershell
# FFUF directory fuzzing
ffuf -u https://example.com/FUZZ `
  -w C:\Users\YourUsername\security-tools\wordlists\SecLists\Discovery\Web-Content\directory-list-2.3-medium.txt `
  -mc 200,301,302,403 `
  -o ffuf_results.json

# Gobuster directory brute-force
gobuster dir `
  -u https://example.com `
  -w C:\Users\YourUsername\security-tools\wordlists\SecLists\Discovery\Web-Content\common.txt `
  -o gobuster_results.txt
```

### Vulnerability Scanning

```powershell
# Nuclei basic scan
nuclei -u https://example.com -o nuclei_results.txt

# Scan multiple targets with severity filter
nuclei -l targets.txt -severity critical,high -o critical_vulns.txt

# Scan with specific tags
nuclei -l targets.txt -tags cve,xss,sqli -o tagged_results.txt
```

### Port Scanning

```powershell
# Naabu port scan
naabu -host example.com -o ports.txt

# Scan from subdomain list
cat subdomains.txt | naabu -silent -o open_ports.txt

# Nmap detailed scan
nmap -sV -sC example.com -oN nmap_results.txt
```

### Android Application Testing

```powershell
# List connected devices
adb devices

# Install APK
adb install app.apk

# Decompile with JADX
jadx app.apk -d output_folder

# Reverse engineer with APKTool
apktool d app.apk -o app_source

# List running apps with Frida
frida-ps -U

# Attach to app
frida -U -n com.example.app

# Spawn and attach
frida -U -f com.example.app --no-pause
```

### Frida Scripting Example

```powershell
# Create a simple Frida script
$fridaScript = @"
Java.perform(function() {
    var MainActivity = Java.use('com.example.app.MainActivity');
    MainActivity.onCreate.implementation = function() {
        console.log('[+] MainActivity.onCreate called!');
        this.onCreate();
    };
});
"@

$fridaScript | Out-File -FilePath hook.js -Encoding UTF8

# Run the script
frida -U -f com.example.app -l hook.js
```

### API Reconnaissance

```powershell
# Using Shodan (requires API key)
shodan search apache --fields ip_str,port,org,hostnames

# Using Censys (requires API key)
censys search "example.com"
```

---

## 🔧 Troubleshooting

### Issue 1: "Execution Policy" Error

**Error**: `.\ArcReactor.ps1 cannot be loaded because running scripts is disabled`

**Solution**:
```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
```

### Issue 2: Chocolatey Installation Failed

**Solution**:
```powershell
# Manual Chocolatey installation
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
Set-ExecutionPolicy Bypass -Scope Process -Force
iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
```

### Issue 3: Go Tools Not Found

**Solution**:
```powershell
# Add Go bin to PATH
$env:Path += ";$env:USERPROFILE\go\bin"
[Environment]::SetEnvironmentVariable("Path", $env:Path, "User")

# Restart PowerShell
exit
```

### Issue 4: ADB Not Recognized

**Solution**:
```powershell
# Add platform-tools to PATH
$env:Path += ";$env:USERPROFILE\security-tools\platform-tools"
[Environment]::SetEnvironmentVariable("Path", $env:Path, "User")

# Verify
adb version
```

### Issue 5: Frida Connection Failed

**Error**: `Failed to enumerate processes: unable to connect to remote frida-server`

**Solution**:
```powershell
# Check Frida Server is running on device
adb shell "ps | grep frida"

# Restart Frida Server
adb shell "killall frida-server"
adb shell "/data/local/tmp/frida-server &"

# Check Frida versions match
frida --version
adb shell "/data/local/tmp/frida-server --version"
```

### Issue 6: Docker Desktop Won't Start

**Solution**:
```powershell
# Enable WSL2
wsl --install

# Enable Hyper-V
Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All

# Restart computer
shutdown /r /t 0
```

### Issue 7: Antivirus Blocking Tools

**Solution**:

Add Windows Defender exclusions:
```powershell
Add-MpPreference -ExclusionPath "$env:USERPROFILE\security-tools"
Add-MpPreference -ExclusionPath "$env:USERPROFILE\go\bin"
Add-MpPreference -ExclusionPath "C:\ProgramData\chocolatey"
```

### Issue 8: Installation Hanging

**Solution**:
- Check internet connection
- Disable VPN
- Free up disk space (need 20GB+)
- Check log file: `notepad $env:USERPROFILE\security-tools-install.log`

---

## 🔄 Updating Tools

### Update All Tools Script

Create `update-all-tools.ps1`:

```powershell
Write-Host "Updating all security tools..." -ForegroundColor Cyan

# Update Chocolatey packages
Write-Host "[1/4] Updating Chocolatey packages..." -ForegroundColor Yellow
choco upgrade all -y

# Update Python packages
Write-Host "[2/4] Updating Python packages..." -ForegroundColor Yellow
python -m pip install --upgrade pip
python -m pip install --upgrade frida-tools shodan censys

# Update Go tools
Write-Host "[3/4] Updating Go tools..." -ForegroundColor Yellow
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/ffuf/ffuf/v2@latest

# Update Nuclei templates
Write-Host "[4/4] Updating Nuclei templates..." -ForegroundColor Yellow
nuclei -update-templates

Write-Host "All tools updated!" -ForegroundColor Green
```

### Update Individual Tools

```powershell
# Update Nuclei
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Update Subfinder
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Update Frida
python -m pip install --upgrade frida-tools

# Update Nuclei templates (most important - do weekly)
nuclei -update-templates

# Update WordLists
cd $env:USERPROFILE\security-tools\wordlists\SecLists
git pull
```

---

## 🗑️ Uninstallation

### Quick Uninstall

```powershell
# Remove installation directory
Remove-Item -Recurse -Force "$env:USERPROFILE\security-tools"

# Remove Go tools
Remove-Item -Recurse -Force "$env:USERPROFILE\go"

# Remove bug bounty workspace
Remove-Item -Recurse -Force "$env:USERPROFILE\bug-bounty"

# Uninstall Chocolatey packages
choco uninstall git python golang nodejs nmap wireshark docker-desktop -y
```

### Complete Uninstall Script

Create `uninstall-arireactor.ps1`:

```powershell
#Requires -RunAsAdministrator

Write-Host "ArcReactor Uninstaller" -ForegroundColor Red
Write-Host "This will remove ALL installed security tools" -ForegroundColor Yellow
$confirm = Read-Host "Continue? (yes/no)"

if ($confirm -ne "yes") {
    Write-Host "Uninstallation cancelled" -ForegroundColor Yellow
    exit
}

# Remove directories
Write-Host "[1/5] Removing installation directories..." -ForegroundColor Cyan
Remove-Item -Recurse -Force "$env:USERPROFILE\security-tools" -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force "$env:USERPROFILE\go" -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force "$env:USERPROFILE\bug-bounty" -ErrorAction SilentlyContinue

# Uninstall Chocolatey packages
Write-Host "[2/5] Uninstalling Chocolatey packages..." -ForegroundColor Cyan
choco uninstall git python golang nodejs nmap wireshark docker-desktop zap androidstudio -y

# Remove Docker images
Write-Host "[3/5] Removing Docker images..." -ForegroundColor Cyan
docker rmi opensecurity/mobile-security-framework-mobsf -f 2>$null

# Clean PATH
Write-Host "[4/5] Cleaning PATH..." -ForegroundColor Cyan
$currentPath = [Environment]::GetEnvironmentVariable("Path", "User")
$cleanedPath = ($currentPath -split ";") | Where-Object {
    $_ -notlike "*go\bin*" -and
    $_ -notlike "*security-tools*" -and
    $_ -ne ""
} | Join-Object -Separator ";"
[Environment]::SetEnvironmentVariable("Path", $cleanedPath, "User")

# Remove log file
Write-Host "[5/5] Removing log files..." -ForegroundColor Cyan
Remove-Item "$env:USERPROFILE\security-tools-install.log" -ErrorAction SilentlyContinue

Write-Host "Uninstallation complete!" -ForegroundColor Green
Write-Host "Please restart your computer" -ForegroundColor Yellow
```

---

## 🔒 Security Considerations

### Legal and Ethical Use

⚠️ **CRITICAL WARNING**: Unauthorized security testing is illegal

**You MUST have authorization before testing**:
- ✅ Written permission from system owner
- ✅ Signed penetration testing contract
- ✅ Authorized bug bounty program participation
- ✅ Your own systems/applications

**Legal Testing Environments**:
- Personal lab/servers
- Bug bounty platforms (HackerOne, Bugcrowd, Intigriti)
- Authorized penetration testing engagements
- CTF competitions (HackTheBox, TryHackMe)

**NEVER Test Without Permission**:
- ❌ Employer's systems (without explicit authorization)
- ❌ Educational institution networks
- ❌ Government systems
- ❌ Public websites/services
- ❌ Any system you don't own

### Antivirus and Windows Defender

Many tools are flagged as malicious because they:
- Contain exploit code
- Perform network scanning
- Manipulate system processes
- Use obfuscation techniques

**This is expected behavior for legitimate security tools**.

**Recommended Actions**:
1. Download from official sources only
2. Verify file hashes when available
3. Add exclusions to antivirus
4. Use in isolated VMs for unknown tools

### Network Security

Some tools generate significant traffic:
- **Port scanners**: Nmap, Naabu
- **Web crawlers**: Katana
- **Vulnerability scanners**: Nuclei
- **Web fuzzers**: Ffuf, Gobuster

**Best Practices**:
- Only scan authorized targets
- Use rate limiting: `nuclei -rate-limit 50`
- Respect robots.txt
- Use VPN/proxy when appropriate
- Follow responsible disclosure

### Responsible Disclosure

When you find vulnerabilities:

1. **Contact Security Team**:
   - Check for `security.txt`: `https://example.com/.well-known/security.txt`
   - Email: `security@example.com`

2. **Provide Details**:
   - Vulnerability description
   - Steps to reproduce
   - Impact assessment
   - Suggested remediation

3. **Give Time to Fix**:
   - Typically 90 days before public disclosure
   - Coordinate timeline with vendor
   - Respect fix verification process

---


- **HackTheBox**: https://www.hackthebox.com
- **TryHackMe**: https://tryhackme.com
- **PortSwigger Web Security Academy**: https://portswigger.net/web-security

### Bug Bounty Platforms
- **HackerOne**: https://www.hackerone.com
- **Bugcrowd**: https://www.bugcrowd.com
- **Intigriti**: https://www.intigriti.com

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

### How to Contribute
1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## ⚠️ Disclaimer

**IMPORTANT LEGAL NOTICE**

This tool collection is intended for:
- Authorized security testing
- Educational purposes
- Security research
- Bug bounty programs
- Penetration testing with written permission

**Unauthorized use is illegal and may result in**:
- Criminal prosecution
- Civil liability
- Termination of employment
- Blacklisting from bug bounty programs

**By using ArcReactor, you agree to**:
- Use tools only on authorized targets
- Follow all applicable laws
- Accept full responsibility for your actions
- Not hold the author liable for misuse

---

## 🌟 Acknowledgments

- ProjectDiscovery team for excellent Go security tools
- Frida team for dynamic instrumentation framework
- PortSwigger for Burp Suite
- OWASP for ZAP and SecLists
- Daniel Miessler for SecLists

---

**Made with ⚡ by Security Researchers, for Security Researchers**

If you found this helpful, please ⭐ star the repository!

[Report Bug](https://github.com/yourusername/arireactor/issues) • [Request Feature](https://github.com/yourusername/arireactor/issues)

</div>

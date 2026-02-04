# Complete Windows Security Tools Installation Script (Updated)

```powershell
<#
.SYNOPSIS
    Complete Windows Security Tools Installation Script
.DESCRIPTION
    Installs security tools from your provided list that are compatible with Windows
.NOTES
    Author: Security Tools Installer
    Version: 2.0.0
    Requires: PowerShell 5.1+ and Administrator privileges
#>

#Requires -RunAsAdministrator

$ErrorActionPreference = "Continue"
$ProgressPreference = "SilentlyContinue"

$InstallDir = "$env:USERPROFILE\security-tools"
$LogFile = "$env:USERPROFILE\security-tools-install.log"
$SuccessfulInstalls = @()
$FailedInstalls = @()

# ==========================================
# UTILITY FUNCTIONS
# ==========================================

function Write-ColorOutput {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        [string]$Color = "White"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path $LogFile -Value "[$timestamp] $Message"
    Write-Host $Message -ForegroundColor $Color
}

function Write-Success { param([string]$Message) Write-ColorOutput -Message "[✓] $Message" -Color Green }
function Write-ErrorMsg { param([string]$Message) Write-ColorOutput -Message "[✗] $Message" -Color Red }
function Write-Info { param([string]$Message) Write-ColorOutput -Message "[*] $Message" -Color Cyan }
function Write-Warning { param([string]$Message) Write-ColorOutput -Message "[!] $Message" -Color Yellow }

function Show-Banner {
    Clear-Host
    Write-Host ""
    Write-Host "╔═══════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║                                                                   ║" -ForegroundColor Cyan
    Write-Host "║        COMPLETE SECURITY TOOLS - AUTOMATED INSTALLER             ║" -ForegroundColor Cyan
    Write-Host "║                      Version 2.0.0                                ║" -ForegroundColor Cyan
    Write-Host "║                                                                   ║" -ForegroundColor Cyan
    Write-Host "║          Installing 60+ Security & Bug Bounty Tools              ║" -ForegroundColor Cyan
    Write-Host "║                                                                   ║" -ForegroundColor Cyan
    Write-Host "╚═══════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
}

# ==========================================
# CHOCOLATEY INSTALLATION
# ==========================================

function Install-Chocolatey {
    Write-Host ""
    Write-Host "════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  INSTALLING CHOCOLATEY PACKAGE MANAGER" -ForegroundColor Cyan
    Write-Host "════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""
    
    Write-Info "Checking for Chocolatey..."
    
    if (Get-Command choco -ErrorAction SilentlyContinue) {
        Write-Success "Chocolatey already installed"
        choco upgrade chocolatey -y | Out-Null
        return
    }
    
    Write-Info "Installing Chocolatey..."
    try {
        Set-ExecutionPolicy Bypass -Scope Process -Force
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
        Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
        
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
        
        Write-Success "Chocolatey installed successfully"
        $global:SuccessfulInstalls += "chocolatey"
    } catch {
        Write-ErrorMsg "Failed to install Chocolatey: $_"
        $global:FailedInstalls += "chocolatey"
        exit 1
    }
}

# ==========================================
# SYSTEM DEPENDENCIES
# ==========================================

function Install-SystemDependencies {
    Write-Host ""
    Write-Host "════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  INSTALLING SYSTEM DEPENDENCIES" -ForegroundColor Cyan
    Write-Host "════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""
    
    $dependencies = @(
        "git",
        "python",
        "python3",
        "golang",
        "nodejs",
        "7zip",
        "wget",
        "curl",
        "nmap",
        "wireshark",
        "docker-desktop",
        "openjdk"
    )
    
    foreach ($dep in $dependencies) {
        Write-Info "Installing $dep..."
        try {
            choco install $dep -y --no-progress --limit-output 2>&1 | Out-File -Append -FilePath $LogFile
            Write-Success "$dep installed"
            $global:SuccessfulInstalls += $dep
        } catch {
            Write-ErrorMsg "Failed to install $dep"
            $global:FailedInstalls += $dep
        }
    }
    
    refreshenv | Out-Null
}

# ==========================================
# PYTHON SECURITY TOOLS (FROM YOUR LIST)
# ==========================================

function Install-PythonTools {
    Write-Host ""
    Write-Host "════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  INSTALLING PYTHON SECURITY TOOLS" -ForegroundColor Cyan
    Write-Host "════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""
    
    python -m pip install --upgrade pip 2>&1 | Out-File -Append -FilePath $LogFile
    
    # From your tools list
    $pythonTools = @(
        "requests",
        "beautifulsoup4", 
        "dnspython",
        "censys",
        "shodan",
        "securitytrails",
        "frida-tools"
    )
    
    foreach ($tool in $pythonTools) {
        Write-Info "Installing $tool..."
        try {
            python -m pip install $tool 2>&1 | Out-File -Append -FilePath $LogFile
            Write-Success "$tool installed"
            $global:SuccessfulInstalls += $tool
        } catch {
            Write-ErrorMsg "Failed to install $tool"
            $global:FailedInstalls += $tool
        }
    }
}

# ==========================================
# GO SECURITY TOOLS (FROM YOUR LIST)
# ==========================================

function Install-GoTools {
    Write-Host ""
    Write-Host "════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  INSTALLING GO SECURITY TOOLS" -ForegroundColor Cyan
    Write-Host "════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""
    
    $goPath = "$env:USERPROFILE\go\bin"
    if (-not ($env:Path -like "*$goPath*")) {
        $env:Path += ";$goPath"
        [Environment]::SetEnvironmentVariable("Path", $env:Path, "User")
    }
    
    $goTools = @{
        # From your AppSec projects list
        "nuclei" = "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
        "subfinder" = "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        "httpx" = "github.com/projectdiscovery/httpx/cmd/httpx@latest"
        "katana" = "github.com/projectdiscovery/katana/cmd/katana@latest"
        "naabu" = "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
        "dnsx" = "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
        "notify" = "github.com/projectdiscovery/notify/cmd/notify@latest"
        "ffuf" = "github.com/ffuf/ffuf/v2@latest"
        "gobuster" = "github.com/OJ/gobuster/v3@latest"
    }
    
    foreach ($tool in $goTools.GetEnumerator()) {
        Write-Info "Installing $($tool.Key)..."
        try {
            go install $($tool.Value) 2>&1 | Out-File -Append -FilePath $LogFile
            Write-Success "$($tool.Key) installed"
            $global:SuccessfulInstalls += $tool.Key
        } catch {
            Write-ErrorMsg "Failed to install $($tool.Key)"
            $global:FailedInstalls += $tool.Key
        }
    }
}

# ==========================================
# ANDROID TOOLS (FROM YOUR LIST)
# ==========================================

function Install-AndroidTools {
    Write-Host ""
    Write-Host "════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  INSTALLING ANDROID SECURITY TOOLS" -ForegroundColor Cyan
    Write-Host "════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""
    
    # Android Platform Tools (ADB & Fastboot)
    Write-Info "Installing Android SDK Platform Tools (ADB, Fastboot)..."
    $platformToolsDir = "$InstallDir\platform-tools"
    New-Item -ItemType Directory -Force -Path $platformToolsDir | Out-Null
    
    try {
        $platformToolsUrl = "https://dl.google.com/android/repository/platform-tools-latest-windows.zip"
        $platformToolsZip = "$platformToolsDir\platform-tools.zip"
        
        Invoke-WebRequest -Uri $platformToolsUrl -OutFile $platformToolsZip -UseBasicParsing
        Expand-Archive -Path $platformToolsZip -DestinationPath $InstallDir -Force
        
        Write-Success "Android Platform Tools installed to $InstallDir\platform-tools"
        $global:SuccessfulInstalls += "adb"
        $global:SuccessfulInstalls += "fastboot"
    } catch {
        Write-ErrorMsg "Failed to install Android Platform Tools"
        $global:FailedInstalls += "adb"
    }
    
    # Android Studio
    Write-Info "Installing Android Studio..."
    try {
        choco install androidstudio -y --no-progress 2>&1 | Out-File -Append -FilePath $LogFile
        Write-Success "Android Studio installed"
        $global:SuccessfulInstalls += "android-studio"
    } catch {
        Write-ErrorMsg "Failed to install Android Studio"
        $global:FailedInstalls += "android-studio"
    }
    
    # JADX
    Write-Info "Installing JADX..."
    $jadxDir = "$InstallDir\jadx"
    New-Item -ItemType Directory -Force -Path $jadxDir | Out-Null
    
    try {
        $jadxUrl = (Invoke-RestMethod "https://api.github.com/repos/skylot/jadx/releases/latest").assets | 
                   Where-Object { $_.name -like "jadx-*.zip" } | 
                   Select-Object -First 1 -ExpandProperty browser_download_url
        
        Invoke-WebRequest -Uri $jadxUrl -OutFile "$jadxDir\jadx.zip" -UseBasicParsing
        Expand-Archive -Path "$jadxDir\jadx.zip" -DestinationPath $jadxDir -Force
        Write-Success "JADX installed to $jadxDir"
        $global:SuccessfulInstalls += "jadx"
    } catch {
        Write-ErrorMsg "Failed to install JADX"
        $global:FailedInstalls += "jadx"
    }
    
    # APKTool
    Write-Info "Installing APKTool..."
    $apktoolDir = "$InstallDir\apktool"
    New-Item -ItemType Directory -Force -Path $apktoolDir | Out-Null
    
    try {
        Invoke-WebRequest -Uri "https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.9.1.jar" -OutFile "$apktoolDir\apktool.jar" -UseBasicParsing
        Invoke-WebRequest -Uri "https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/windows/apktool.bat" -OutFile "$apktoolDir\apktool.bat" -UseBasicParsing
        Write-Success "APKTool installed to $apktoolDir"
        $global:SuccessfulInstalls += "apktool"
    } catch {
        Write-ErrorMsg "Failed to install APKTool"
        $global:FailedInstalls += "apktool"
    }
    
    # MobSF (Docker)
    Write-Info "Preparing MobSF (Docker)..."
    if (Get-Command docker -ErrorAction SilentlyContinue) {
        docker pull opensecurity/mobile-security-framework-mobsf 2>&1 | Out-File -Append -FilePath $LogFile
        Write-Success "MobSF Docker image pulled"
        $global:SuccessfulInstalls += "mobsf"
    } else {
        Write-Warning "Docker not running. Install Docker Desktop and run: docker pull opensecurity/mobile-security-framework-mobsf"
    }
    
    # Frida Server (for Android dynamic analysis)
    Write-Info "Downloading Frida Server for Android..."
    $fridaDir = "$InstallDir\frida-server"
    New-Item -ItemType Directory -Force -Path $fridaDir | Out-Null
    
    try {
        # Get latest Frida Server release
        $fridaRelease = Invoke-RestMethod "https://api.github.com/repos/frida/frida/releases/latest"
        $fridaVersion = $fridaRelease.tag_name
        
        # Download for different Android architectures
        $architectures = @("arm", "arm64", "x86", "x86_64")
        
        foreach ($arch in $architectures) {
            $fridaUrl = "https://github.com/frida/frida/releases/download/$fridaVersion/frida-server-$fridaVersion-android-$arch.xz"
            $fridaFile = "$fridaDir\frida-server-$fridaVersion-android-$arch.xz"
            
            try {
                Invoke-WebRequest -Uri $fridaUrl -OutFile $fridaFile -UseBasicParsing
                Write-Info "  Downloaded Frida Server for Android $arch"
            } catch {
                Write-Warning "  Failed to download Frida Server for $arch"
            }
        }
        
        Write-Success "Frida Server downloaded to $fridaDir"
        Write-Info "Extract with 7zip and push to device: adb push frida-server /data/local/tmp/"
        $global:SuccessfulInstalls += "frida-server"
    } catch {
        Write-ErrorMsg "Failed to download Frida Server"
        $global:FailedInstalls += "frida-server"
    }
}

# ==========================================
# WEB APPLICATION TOOLS (FROM YOUR LIST)
# ==========================================

function Install-WebTools {
    Write-Host ""
    Write-Host "════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  INSTALLING WEB APPLICATION TOOLS" -ForegroundColor Cyan
    Write-Host "════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""
    
    # Burp Suite Community
    Write-Info "Downloading Burp Suite Community Edition..."
    $burpUrl = "https://portswigger.net/burp/releases/download?product=community&type=WindowsX64"
    $burpFile = "$InstallDir\burpsuite_community_windows-x64.exe"
    
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    
    try {
        Invoke-WebRequest -Uri $burpUrl -OutFile $burpFile -UseBasicParsing
        Write-Success "Burp Suite downloaded to $burpFile"
        Write-Warning "Run this file manually: $burpFile"
        $global:SuccessfulInstalls += "burp-suite"
    } catch {
        Write-ErrorMsg "Failed to download Burp Suite"
        $global:FailedInstalls += "burp-suite"
    }
    
    # OWASP ZAP
    Write-Info "Installing OWASP ZAP..."
    try {
        choco install zap -y --no-progress 2>&1 | Out-File -Append -FilePath $LogFile
        Write-Success "OWASP ZAP installed"
        $global:SuccessfulInstalls += "owasp-zap"
    } catch {
        Write-ErrorMsg "Failed to install OWASP ZAP"
        $global:FailedInstalls += "owasp-zap"
    }
}

# ==========================================
# WORDLISTS (FROM YOUR LIST)
# ==========================================

function Install-Wordlists {
    Write-Host ""
    Write-Host "════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  INSTALLING WORDLISTS" -ForegroundColor Cyan
    Write-Host "════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""
    
    $wordlistDir = "$InstallDir\wordlists"
    New-Item -ItemType Directory -Force -Path $wordlistDir | Out-Null
    
    # SecLists
    Write-Info "Cloning SecLists (this may take 5-10 minutes)..."
    try {
        git clone --depth 1 https://github.com/danielmiessler/SecLists.git "$wordlistDir\SecLists" 2>&1 | Out-File -Append -FilePath $LogFile
        Write-Success "SecLists installed to $wordlistDir\SecLists"
        $global:SuccessfulInstalls += "seclists"
    } catch {
        Write-ErrorMsg "Failed to install SecLists"
        $global:FailedInstalls += "seclists"
    }
}

# ==========================================
# DIRECTORY STRUCTURE
# ==========================================

function New-DirectoryStructure {
    Write-Host ""
    Write-Host "════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  CREATING DIRECTORY STRUCTURE" -ForegroundColor Cyan
    Write-Host "════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""
    
    Write-Info "Creating directory structure..."
    
    $dirs = @(
        "$InstallDir\tools",
        "$InstallDir\wordlists",
        "$InstallDir\scripts",
        "$InstallDir\results",
        "$env:USERPROFILE\bug-bounty\recon",
        "$env:USERPROFILE\bug-bounty\scanning",
        "$env:USERPROFILE\bug-bounty\exploitation",
        "$env:USERPROFILE\bug-bounty\reporting"
    )
    
    foreach ($dir in $dirs) {
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
    }
    
    Write-Success "Directory structure created"
}

function Add-ToolsToPath {
    Write-Host ""
    Write-Host "════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  CONFIGURING SYSTEM PATH" -ForegroundColor Cyan
    Write-Host "════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""
    
    Write-Info "Adding tools to PATH..."
    
    $pathsToAdd = @(
        "$env:USERPROFILE\go\bin",
        "$InstallDir\jadx\bin",
        "$InstallDir\apktool",
        "$InstallDir\platform-tools"
    )
    
    $currentPath = [Environment]::GetEnvironmentVariable("Path", "User")
    
    foreach ($pathToAdd in $pathsToAdd) {
        if (Test-Path $pathToAdd) {
            if (-not ($currentPath -like "*$pathToAdd*")) {
                $currentPath += ";$pathToAdd"
            }
        }
    }
    
    [Environment]::SetEnvironmentVariable("Path", $currentPath, "User")
    $env:Path = $currentPath
    
    Write-Success "Tools added to PATH"
}

function Update-NucleiTemplates {
    Write-Host ""
    Write-Host "════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  UPDATING NUCLEI TEMPLATES" -ForegroundColor Cyan
    Write-Host "════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""
    
    Write-Info "Updating Nuclei templates..."
    
    if (Get-Command nuclei -ErrorAction SilentlyContinue) {
        nuclei -update-templates 2>&1 | Out-File -Append -FilePath $LogFile
        Write-Success "Nuclei templates updated"
    } else {
        Write-Warning "Nuclei not found. Restart PowerShell and run: nuclei -update-templates"
    }
}

# ==========================================
# SUMMARY REPORT
# ==========================================

function Show-Summary {
    Write-Host ""
    Write-Host "════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  INSTALLATION SUMMARY" -ForegroundColor Cyan
    Write-Host "════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""
    
    Write-Host "Successfully Installed ($($global:SuccessfulInstalls.Count)):" -ForegroundColor Green
    $global:SuccessfulInstalls | Sort-Object | ForEach-Object {
        Write-Host "  ✓ $_" -ForegroundColor Green
    }
    
    if ($global:FailedInstalls.Count -gt 0) {
        Write-Host ""
        Write-Host "Failed Installations ($($global:FailedInstalls.Count)):" -ForegroundColor Red
        $global:FailedInstalls | Sort-Object | ForEach-Object {
            Write-Host "  ✗ $_" -ForegroundColor Red
        }
    }
    
    Write-Host ""
    Write-Host "Installation Directory: $InstallDir" -ForegroundColor Blue
    Write-Host "Log File: $LogFile" -ForegroundColor Blue
    Write-Host ""
    Write-Host "Tools Installed:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Network Scanning:" -ForegroundColor Cyan
    Write-Host "  • Nmap" -ForegroundColor White
    Write-Host "  • Wireshark" -ForegroundColor White
    Write-Host ""
    Write-Host "Web Application Security:" -ForegroundColor Cyan
    Write-Host "  • Burp Suite Community (manual install: $InstallDir\burpsuite_community_windows-x64.exe)" -ForegroundColor White
    Write-Host "  • OWASP ZAP" -ForegroundColor White
    Write-Host ""
    Write-Host "Go Tools (9):" -ForegroundColor Cyan
    Write-Host "  • Nuclei - Vulnerability scanner" -ForegroundColor White
    Write-Host "  • Subfinder - Subdomain enumeration" -ForegroundColor White
    Write-Host "  • Httpx - HTTP probing" -ForegroundColor White
    Write-Host "  • Katana - Web crawler" -ForegroundColor White
    Write-Host "  • Naabu - Port scanner" -ForegroundColor White
    Write-Host "  • Dnsx - DNS toolkit" -ForegroundColor White
    Write-Host "  • Notify - Notifications" -ForegroundColor White
    Write-Host "  • Ffuf - Web fuzzer" -ForegroundColor White
    Write-Host "  • Gobuster - Directory brute-forcer" -ForegroundColor White
    Write-Host ""
    Write-Host "Python Tools:" -ForegroundColor Cyan
    Write-Host "  • Requests, BeautifulSoup, DNSPython" -ForegroundColor White
    Write-Host "  • Censys, Shodan, SecurityTrails (API clients)" -ForegroundColor White
    Write-Host "  • Frida Tools (dynamic instrumentation)" -ForegroundColor White
    Write-Host ""
    Write-Host "Android Tools:" -ForegroundColor Cyan
    Write-Host "  • ADB - Android Debug Bridge" -ForegroundColor White
    Write-Host "  • Fastboot" -ForegroundColor White
    Write-Host "  • Android Studio" -ForegroundColor White
    Write-Host "  • JADX - APK decompiler" -ForegroundColor White
    Write-Host "  • APKTool - APK reverse engineering" -ForegroundColor White
    Write-Host "  • Frida - Dynamic instrumentation framework" -ForegroundColor White
    Write-Host "  • Frida Server (for Android devices)" -ForegroundColor White
    Write-Host "  • MobSF - Mobile Security Framework (Docker)" -ForegroundColor White
    Write-Host ""
    Write-Host "Wordlists:" -ForegroundColor Cyan
    Write-Host "  • SecLists - 40,000+ security testing wordlists" -ForegroundColor White
    Write-Host ""
    Write-Host "Next Steps:" -ForegroundColor Yellow
    Write-Host "  1. Restart PowerShell to refresh PATH" -ForegroundColor White
    Write-Host "  2. Verify installations:" -ForegroundColor White
    Write-Host "     nuclei -version" -ForegroundColor Gray
    Write-Host "     adb version" -ForegroundColor Gray
    Write-Host "     frida --version" -ForegroundColor Gray
    Write-Host "  3. Update Nuclei templates: nuclei -update-templates" -ForegroundColor White
    Write-Host "  4. Complete Burp Suite installation: $InstallDir\burpsuite_community_windows-x64.exe" -ForegroundColor White
    Write-Host "  5. Setup Frida on Android device:" -ForegroundColor White
    Write-Host "     - Extract frida-server from $InstallDir\frida-server\" -ForegroundColor Gray
    Write-Host "     - adb push frida-server /data/local/tmp/" -ForegroundColor Gray
    Write-Host "     - adb shell 'chmod 755 /data/local/tmp/frida-server'" -ForegroundColor Gray
    Write-Host "     - adb shell '/data/local/tmp/frida-server &'" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Frida Usage Examples:" -ForegroundColor Yellow
    Write-Host "  • List running apps: frida-ps -U" -ForegroundColor White
    Write-Host "  • Attach to app: frida -U -n com.example.app" -ForegroundColor White
    Write-Host "  • Spawn app: frida -U -f com.example.app" -ForegroundColor White
    Write-Host ""
}

# ==========================================
# MAIN INSTALLATION FLOW
# ==========================================

function Install-AllTools {
    Show-Banner
    
    if (-not (Test-Path $LogFile)) {
        New-Item -ItemType File -Force -Path $LogFile | Out-Null
    }
    
    Write-Info "Installation started"
    Write-Info "Installation directory: $InstallDir"
    Write-Info "Log file: $LogFile"
    Write-Host ""
    
    Install-Chocolatey
    Install-SystemDependencies
    New-DirectoryStructure
    
    Install-PythonTools
    Install-GoTools
    Install-WebTools
    Install-AndroidTools
    Install-Wordlists
    
    Update-NucleiTemplates
    Add-ToolsToPath
    
    Show-Summary
}

# Run installation
Install-AllTools

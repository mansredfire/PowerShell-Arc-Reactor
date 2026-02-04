<#
.SYNOPSIS
    Windows-Exclusive Security Tools Installation Script
.DESCRIPTION
    Installs security tools that run natively on Windows or are Windows-specific
    Excludes tools already in Kali Linux
.NOTES
    Author: Security Tools Installer
    Version: 1.0.0
    Requires: PowerShell 5.1+ and Administrator privileges
#>

#Requires -RunAsAdministrator

$ErrorActionPreference = "Continue"
$ProgressPreference = "SilentlyContinue"

$InstallDir = "$env:USERPROFILE\security-tools"
$LogFile = "$env:USERPROFILE\security-tools-install.log"
$SuccessfulInstalls = @()
$FailedInstalls = @()

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
    Write-Host ""
    Write-Host "╔═══════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║                                                                   ║" -ForegroundColor Cyan
    Write-Host "║        WINDOWS SECURITY TOOLS - AUTOMATED INSTALLER              ║" -ForegroundColor Cyan
    Write-Host "║                      Version 1.0.0                                ║" -ForegroundColor Cyan
    Write-Host "║                                                                   ║" -ForegroundColor Cyan
    Write-Host "║          Installing Windows-Native Security Tools                ║" -ForegroundColor Cyan
    Write-Host "║                                                                   ║" -ForegroundColor Cyan
    Write-Host "╚═══════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
}

function Install-Chocolatey {
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
    } catch {
        Write-ErrorMsg "Failed to install Chocolatey: $_"
        exit 1
    }
}

function Install-WindowsDependencies {
    Write-Host ""
    Write-Host "════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  INSTALLING WINDOWS DEPENDENCIES" -ForegroundColor Cyan
    Write-Host "════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""
    
    $dependencies = @(
        "git",
        "python",
        "python3",
        "golang",
        "nodejs",
        "vscode",
        "7zip",
        "wget",
        "curl",
        "jq",
        "docker-desktop",
        "virtualbox",
        "wireshark",
        "nmap",
        "processhacker",
        "sysinternals",
        "dotnet-sdk",
        "dotnetcore-sdk",
        "visualstudio2022buildtools",
        "windows-sdk-10",
        "microsoft-windows-terminal"
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

function Install-WindowsSpecificTools {
    Write-Host ""
    Write-Host "════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  INSTALLING WINDOWS-SPECIFIC SECURITY TOOLS" -ForegroundColor Cyan
    Write-Host "════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""
    
    # Sysinternals Suite (Windows-exclusive)
    Write-Info "Installing Sysinternals Suite..."
    try {
        choco install sysinternals -y --no-progress 2>&1 | Out-File -Append -FilePath $LogFile
        Write-Success "Sysinternals Suite installed"
        $global:SuccessfulInstalls += "sysinternals"
    } catch {
        Write-ErrorMsg "Failed to install Sysinternals"
        $global:FailedInstalls += "sysinternals"
    }
    
    # Process Hacker (Windows-exclusive)
    Write-Info "Installing Process Hacker..."
    try {
        choco install processhacker -y --no-progress 2>&1 | Out-File -Append -FilePath $LogFile
        Write-Success "Process Hacker installed"
        $global:SuccessfulInstalls += "processhacker"
    } catch {
        Write-ErrorMsg "Failed to install Process Hacker"
        $global:FailedInstalls += "processhacker"
    }
    
    # x64dbg (Windows debugger)
    Write-Info "Installing x64dbg..."
    try {
        choco install x64dbg.portable -y --no-progress 2>&1 | Out-File -Append -FilePath $LogFile
        Write-Success "x64dbg installed"
        $global:SuccessfulInstalls += "x64dbg"
    } catch {
        Write-ErrorMsg "Failed to install x64dbg"
        $global:FailedInstalls += "x64dbg"
    }
    
    # dnSpy (.NET debugger/decompiler - Windows-exclusive)
    Write-Info "Installing dnSpy..."
    $dnspyDir = "$InstallDir\dnspy"
    New-Item -ItemType Directory -Force -Path $dnspyDir | Out-Null
    
    try {
        $dnspyUrl = (Invoke-RestMethod "https://api.github.com/repos/dnSpy/dnSpy/releases/latest").assets | 
                    Where-Object { $_.name -like "dnSpy-net-win64.zip" } | 
                    Select-Object -First 1 -ExpandProperty browser_download_url
        
        Invoke-WebRequest -Uri $dnspyUrl -OutFile "$dnspyDir\dnspy.zip" -UseBasicParsing
        Expand-Archive -Path "$dnspyDir\dnspy.zip" -DestinationPath $dnspyDir -Force
        Write-Success "dnSpy installed to $dnspyDir"
        $global:SuccessfulInstalls += "dnspy"
    } catch {
        Write-ErrorMsg "Failed to install dnSpy"
        $global:FailedInstalls += "dnspy"
    }
    
    # ILSpy (.NET decompiler - Windows-exclusive)
    Write-Info "Installing ILSpy..."
    try {
        choco install ilspy -y --no-progress 2>&1 | Out-File -Append -FilePath $LogFile
        Write-Success "ILSpy installed"
        $global:SuccessfulInstalls += "ilspy"
    } catch {
        Write-ErrorMsg "Failed to install ILSpy"
        $global:FailedInstalls += "ilspy"
    }
    
    # Detect It Easy (Modern alternative to PEiD)
    Write-Info "Installing Detect It Easy..."
    $dieDir = "$InstallDir\detect-it-easy"
    New-Item -ItemType Directory -Force -Path $dieDir | Out-Null
    
    try {
        $dieUrl = (Invoke-RestMethod "https://api.github.com/repos/horsicq/Detect-It-Easy/releases/latest").assets | 
                  Where-Object { $_.name -like "die_win64_portable*.zip" } | 
                  Select-Object -First 1 -ExpandProperty browser_download_url
        
        Invoke-WebRequest -Uri $dieUrl -OutFile "$dieDir\die.zip" -UseBasicParsing
        Expand-Archive -Path "$dieDir\die.zip" -DestinationPath $dieDir -Force
        Write-Success "Detect It Easy installed to $dieDir"
        $global:SuccessfulInstalls += "detect-it-easy"
    } catch {
        Write-ErrorMsg "Failed to install Detect It Easy"
        $global:FailedInstalls += "detect-it-easy"
    }
}

function Install-BurpSuite {
    Write-Host ""
    Write-Host "════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  INSTALLING BURP SUITE COMMUNITY" -ForegroundColor Cyan
    Write-Host "════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""
    
    Write-Info "Downloading Burp Suite Community Edition..."
    
    $burpUrl = "https://portswigger.net/burp/releases/download?product=community&type=WindowsX64"
    $burpFile = "$InstallDir\burpsuite_community_windows-x64.exe"
    
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    
    try {
        Invoke-WebRequest -Uri $burpUrl -OutFile $burpFile -UseBasicParsing
        Write-Success "Burp Suite downloaded to $burpFile"
        Write-Warning "Run this file manually to complete installation: $burpFile"
        $global:SuccessfulInstalls += "burp-suite-download"
    } catch {
        Write-ErrorMsg "Failed to download Burp Suite"
        $global:FailedInstalls += "burp-suite"
    }
}

function Install-OWASPZAP {
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

function Install-PythonTools {
    Write-Host ""
    Write-Host "════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  INSTALLING PYTHON SECURITY TOOLS" -ForegroundColor Cyan
    Write-Host "════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""
    
    python -m pip install --upgrade pip 2>&1 | Out-File -Append -FilePath $LogFile
    
    $pythonTools = @(
        "impacket",
        "crackmapexec",
        "bloodhound",
        "mitm6",
        "responder",
        "pywerview",
        "ldapdomaindump",
        "kerbrute",
        "requests",
        "beautifulsoup4",
        "selenium",
        "playwright",
        "pycryptodome",
        "pyjwt",
        "shodan",
        "censys",
        "arjun",
        "xsstrike",
        "sublist3r"
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
    
    Write-Info "Installing Playwright browsers..."
    python -m playwright install chromium 2>&1 | Out-File -Append -FilePath $LogFile
}

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
        "nuclei" = "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
        "subfinder" = "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        "httpx" = "github.com/projectdiscovery/httpx/cmd/httpx@latest"
        "katana" = "github.com/projectdiscovery/katana/cmd/katana@latest"
        "dnsx" = "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
        "interactsh" = "github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"
        "notify" = "github.com/projectdiscovery/notify/cmd/notify@latest"
        "ffuf" = "github.com/ffuf/ffuf/v2@latest"
        "gobuster" = "github.com/OJ/gobuster/v3@latest"
        "amass" = "github.com/owasp-amass/amass/v4/...@master"
        "assetfinder" = "github.com/tomnomnom/assetfinder@latest"
        "gau" = "github.com/lc/gau/v2/cmd/gau@latest"
        "waybackurls" = "github.com/tomnomnom/waybackurls@latest"
        "gf" = "github.com/tomnomnom/gf@latest"
        "anew" = "github.com/tomnomnom/anew@latest"
        "unfurl" = "github.com/tomnomnom/unfurl@latest"
        "qsreplace" = "github.com/tomnomnom/qsreplace@latest"
        "dalfox" = "github.com/hahwul/dalfox/v2@latest"
        "kxss" = "github.com/Emoe/kxss@latest"
        "crlfuzz" = "github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest"
        "gospider" = "github.com/jaeles-project/gospider@latest"
        "hakrawler" = "github.com/hakluke/hakrawler@latest"
        "gitleaks" = "github.com/gitleaks/gitleaks/v8@latest"
        "trufflehog" = "github.com/trufflesecurity/trufflehog/v3@latest"
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

function Install-AndroidSDKTools {
    Write-Host ""
    Write-Host "════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  INSTALLING ANDROID SDK & ADB" -ForegroundColor Cyan
    Write-Host "════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""
    
    # Install Android SDK Platform Tools (includes ADB)
    Write-Info "Installing Android SDK Platform Tools (ADB, Fastboot)..."
    
    $platformToolsDir = "$InstallDir\platform-tools"
    New-Item -ItemType Directory -Force -Path $platformToolsDir | Out-Null
    
    try {
        $platformToolsUrl = "https://dl.google.com/android/repository/platform-tools-latest-windows.zip"
        $platformToolsZip = "$platformToolsDir\platform-tools.zip"
        
        Invoke-WebRequest -Uri $platformToolsUrl -OutFile $platformToolsZip -UseBasicParsing
        Expand-Archive -Path $platformToolsZip -DestinationPath $InstallDir -Force
        
        Write-Success "Android Platform Tools installed to $InstallDir\platform-tools"
        Write-Info "ADB location: $InstallDir\platform-tools\adb.exe"
        
        $global:SuccessfulInstalls += "adb"
        $global:SuccessfulInstalls += "fastboot"
    } catch {
        Write-ErrorMsg "Failed to install Android Platform Tools"
        $global:FailedInstalls += "adb"
    }
    
    # Android Studio (full IDE)
    Write-Info "Installing Android Studio..."
    try {
        choco install androidstudio -y --no-progress 2>&1 | Out-File -Append -FilePath $LogFile
        Write-Success "Android Studio installed"
        Write-Info "After installation, run Android Studio and install SDK via SDK Manager"
        $global:SuccessfulInstalls += "android-studio"
    } catch {
        Write-ErrorMsg "Failed to install Android Studio"
        $global:FailedInstalls += "android-studio"
    }
    
    # Scrcpy (screen mirroring - useful for mobile testing)
    Write-Info "Installing scrcpy (Android screen mirroring)..."
    try {
        choco install scrcpy -y --no-progress 2>&1 | Out-File -Append -FilePath $LogFile
        Write-Success "scrcpy installed"
        $global:SuccessfulInstalls += "scrcpy"
    } catch {
        Write-ErrorMsg "Failed to install scrcpy"
        $global:FailedInstalls += "scrcpy"
    }
}

function Install-AndroidTools {
    Write-Host ""
    Write-Host "════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  INSTALLING ANDROID REVERSE ENGINEERING TOOLS" -ForegroundColor Cyan
    Write-Host "════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""
    
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
    Write-Info "Installing MobSF (Docker)..."
    if (Get-Command docker -ErrorAction SilentlyContinue) {
        docker pull opensecurity/mobile-security-framework-mobsf 2>&1 | Out-File -Append -FilePath $LogFile
        Write-Success "MobSF Docker image pulled"
        Write-Info "Run with: docker run -it -p 8000:8000 opensecurity/mobile-security-framework-mobsf"
        $global:SuccessfulInstalls += "mobsf"
    } else {
        Write-Warning "Docker not installed. Skipping MobSF"
    }
}

function Install-ReverseEngineeringTools {
    Write-Host ""
    Write-Host "════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  INSTALLING REVERSE ENGINEERING TOOLS" -ForegroundColor Cyan
    Write-Host "════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""
    
    # Ghidra
    Write-Info "Installing Ghidra..."
    $ghidraDir = "$InstallDir\ghidra"
    New-Item -ItemType Directory -Force -Path $ghidraDir | Out-Null
    
    try {
        $ghidraUrl = (Invoke-RestMethod "https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/latest").assets | 
                     Where-Object { $_.name -like "ghidra_*.zip" } | 
                     Select-Object -First 1 -ExpandProperty browser_download_url
        
        Invoke-WebRequest -Uri $ghidraUrl -OutFile "$ghidraDir\ghidra.zip" -UseBasicParsing
        Expand-Archive -Path "$ghidraDir\ghidra.zip" -DestinationPath $ghidraDir -Force
        Write-Success "Ghidra installed to $ghidraDir"
        Write-Info "Run Ghidra from: $ghidraDir\ghidra_*\ghidraRun.bat"
        $global:SuccessfulInstalls += "ghidra"
    } catch {
        Write-ErrorMsg "Failed to install Ghidra"
        $global:FailedInstalls += "ghidra"
    }
    
    # IDA Free (Windows version)
    Write-Info "Downloading IDA Free..."
    Write-Warning "IDA Free must be downloaded manually from: https://hex-rays.com/ida-free/"
    Write-Info "After download, install to: $InstallDir\ida-free"
}

function Install-Wordlists {
    Write-Host ""
    Write-Host "════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  INSTALLING WORDLISTS" -ForegroundColor Cyan
    Write-Host "════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""
    
    $wordlistDir = "$InstallDir\wordlists"
    New-Item -ItemType Directory -Force -Path $wordlistDir | Out-Null
    
    # SecLists
    Write-Info "Cloning SecLists..."
    try {
        git clone --depth 1 https://github.com/danielmiessler/SecLists.git "$wordlistDir\SecLists" 2>&1 | Out-File -Append -FilePath $LogFile
        Write-Success "SecLists installed"
        $global:SuccessfulInstalls += "seclists"
    } catch {
        Write-ErrorMsg "Failed to install SecLists"
        $global:FailedInstalls += "seclists"
    }
    
    # PayloadsAllTheThings
    Write-Info "Cloning PayloadsAllTheThings..."
    try {
        git clone --depth 1 https://github.com/swisskyrepo/PayloadsAllTheThings.git "$wordlistDir\PayloadsAllTheThings" 2>&1 | Out-File -Append -FilePath $LogFile
        Write-Success "PayloadsAllTheThings installed"
        $global:SuccessfulInstalls += "payloadsallthethings"
    } catch {
        Write-ErrorMsg "Failed to install PayloadsAllTheThings"
        $global:FailedInstalls += "payloadsallthethings"
    }
}

function New-DirectoryStructure {
    Write-Info "Creating directory structure..."
    
    $dirs = @(
        "$InstallDir\tools",
        "$InstallDir\wordlists",
        "$InstallDir\scripts",
        "$InstallDir\results",
        "$InstallDir\configs",
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
    Write-Info "Adding tools to PATH..."
    
    $pathsToAdd = @(
        "$env:USERPROFILE\go\bin",
        "$InstallDir\jadx\bin",
        "$InstallDir\apktool",
        "$InstallDir\platform-tools",
        "$InstallDir\ghidra",
        "$InstallDir\dnspy",
        "$InstallDir\detect-it-easy"
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
    Write-Info "Updating Nuclei templates..."
    
    if (Get-Command nuclei -ErrorAction SilentlyContinue) {
        nuclei -update-templates 2>&1 | Out-File -Append -FilePath $LogFile
        Write-Success "Nuclei templates updated"
    }
}

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
    Write-Host "Windows-Specific Tools Installed:" -ForegroundColor Yellow
    Write-Host "  • Sysinternals Suite (Process Monitor, Process Explorer, etc.)" -ForegroundColor White
    Write-Host "  • Process Hacker (Advanced process monitoring)" -ForegroundColor White
    Write-Host "  • x64dbg (Windows debugger)" -ForegroundColor White
    Write-Host "  • dnSpy (.NET debugger/decompiler)" -ForegroundColor White
    Write-Host "  • ILSpy (.NET decompiler)" -ForegroundColor White
    Write-Host "  • Detect It Easy (PE file analyzer)" -ForegroundColor White
    Write-Host ""
    Write-Host "Android Tools Installed:" -ForegroundColor Yellow
    Write-Host "  • ADB (Android Debug Bridge)" -ForegroundColor White
    Write-Host "  • Fastboot" -ForegroundColor White
    Write-Host "  • Android Studio" -ForegroundColor White
    Write-Host "  • JADX (APK decompiler)" -ForegroundColor White
    Write-Host "  • APKTool (APK reverse engineering)" -ForegroundColor White
    Write-Host "  • scrcpy (Screen mirroring)" -ForegroundColor White
    Write-Host ""
    Write-Host "Next Steps:" -ForegroundColor Yellow
    Write-Host "  1. Restart PowerShell or run: refreshenv" -ForegroundColor White
    Write-Host "  2. Verify ADB: adb version" -ForegroundColor White
    Write-Host "  3. Verify Go tools: nuclei -version" -ForegroundColor White
    Write-Host "  4. Verify Python tools: python -m pip list" -ForegroundColor White
    Write-Host "  5. Complete Burp Suite installation: $InstallDir\burpsuite_community_windows-x64.exe" -ForegroundColor White
    Write-Host "  6. Launch Android Studio to complete SDK setup" -ForegroundColor White
    Write-Host ""
}

function Install-AllTools {
    Show-Banner
    
    if (-not (Test-Path $LogFile)) {
        New-Item -ItemType File -Force -Path $LogFile | Out-Null
    }
    
    Write-Info "Installation started - Windows-specific tools only"
    Write-Info "Installation directory: $InstallDir"
    Write-Info "Log file: $LogFile"
    Write-Host ""
    
    Install-Chocolatey
    Install-WindowsDependencies
    New-DirectoryStructure
    
    Install-WindowsSpecificTools
    Install-PythonTools
    Install-GoTools
    Install-BurpSuite
    Install-OWASPZAP
    Install-AndroidSDKTools
    Install-AndroidTools
    Install-ReverseEngineeringTools
    Install-Wordlists
    
    Update-NucleiTemplates
    Add-ToolsToPath
    
    Show-Summary
}

Install-AllTools

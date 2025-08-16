# InjectedHackHunter1.ps1
# Basic scanner to look for suspicious hack/injection activity

Write-Host "=== InjectedHackHunter1 started ===" -ForegroundColor Cyan
Write-Host "Scanning processes, modules and common folders..." -ForegroundColor Yellow

# Suspicious keywords to scan for
$suspiciousKeywords = @(
    "inject", "dll", "hack", "cheat", "aimbot", "trigger",
    "bypass", "esp", "xray", "loader", "crack", "ghost",
    "clicker", "forgeinject", "fabricinject", "client"
)

# Scan running processes
Write-Host "`n[1] Checking running processes..."
Get-Process | ForEach-Object {
    $procName = $_.Name.ToLower()
    foreach ($kw in $suspiciousKeywords) {
        if ($procName -like "*$kw*") {
            Write-Host "⚠ Suspicious process: $procName (ID: $($_.Id))" -ForegroundColor Red
        }
    }
}

# Scan only Minecraft (javaw.exe) loaded modules
Write-Host "`n[2] Checking Minecraft DLLs..."
$mc = Get-Process javaw -ErrorAction SilentlyContinue
if ($mc) {
    try {
        foreach ($m in $mc.Modules) {
            $modName = $m.ModuleName.ToLower()
            foreach ($kw in $suspiciousKeywords) {
                if ($modName -like "*$kw*") {
                    Write-Host "⚠️ Suspicious module in Minecraft (javaw.exe): $modName" -ForegroundColor Red
                }
            }
        }
    } catch {
        Write-Host "Could not scan Minecraft modules (access denied)." -ForegroundColor Yellow
    }
} else {
    Write-Host "Minecraft (javaw.exe) not running." -ForegroundColor Yellow
}


# Scan Program Files and Program Files (x86)
Write-Host "`n[3] Checking Program Files folders..."
$programFilesPaths = @(
    "$env:ProgramFiles",
    "${env:ProgramFiles(x86)}"
)

foreach ($folder in $programFilesPaths) {
    if (Test-Path $folder) {
        Get-ChildItem -Path $folder -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
            $fname = $_.Name.ToLower()
            foreach ($kw in $suspiciousKeywords) {
                if ($fname -like "*$kw*") {
                    Write-Host "⚠ Suspicious file found: $($_.FullName)" -ForegroundColor Red
                }
            }
        }
    }
}

Write-Host "`n=== Scan finished ===" -ForegroundColor Cyan

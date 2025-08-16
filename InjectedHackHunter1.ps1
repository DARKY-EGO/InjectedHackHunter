<# 
InjectedHackHunter1.ps1
Purpose: Detect injected Minecraft hacks by scanning the live javaw.exe process for loaded DLLs,
         hashing modules, applying heuristics for suspicious paths and keywords, and noting common injector tools.
Author: You
Usage:
  1) Start Minecraft (javaw.exe) and join a world/server.
  2) Open Windows PowerShell (64-bit) as Administrator.
  3) Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
  4) & ".\InjectedHackHunter1.ps1"
Notes:
  - No script can hit 100% detection; this design aims for high coverage on public/semi-private injectables.
  - Keep the KnownHackHashes and KeywordHints updated from your ops.
#>

#region --- Admin + Basics ---
function Ensure-Admin {
    $IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
    if (-not $IsAdmin) {
        Write-Host "[i] Relaunching PowerShell as Administrator..." -ForegroundColor Yellow
        Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
        exit
    }
}
Ensure-Admin

$ErrorActionPreference = "SilentlyContinue"
function NowStamp { (Get-Date).ToString("yyyy-MM-dd_HH-mm-ss") }
function Sha256($p) { try { (Get-FileHash -Path $p -Algorithm SHA256 -ErrorAction Stop).Hash } catch { $null } }
function Shorten($p) { if ($null -eq $p) { "" } else { $p -replace [regex]::Escape($env:USERPROFILE), "~" } }

#region --- Config: Hashes, Keywords, Paths, Injectors ---
# Replace/add with real hashes you collect (uppercase SHA-256)
$KnownHackHashes = @(
    # PLACEHOLDERS — update these with real values you confirm in screenshares
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
    "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
) | ForEach-Object { $_.ToUpperInvariant() }

# Broad hints seen across ghost clients & injectors (process names, module names, exports, strings)
$KeywordHints = @(
    # Ghost/clients
    "vape","sigma","novoline","rise","raven","meteor","aristois","impact","wurst",
    "liquidbounce","kami","kamiblue","inertia","salhack","hydra","abyss","future",
    "rusherhack","bleachhack","pandaware","drip","flux","crystalware","moon","nekoclient",
    # Injection frameworks / overlays / hooks
    "minhook","kiero","detours","polyhook","blackbone","overlay","presenthook","d3d11",
    "dxgi","dinput8","opengl32","swapchain","sigscan","patternscan","hook","inject","loader",
    # Tools
    "cheatengine","processhacker","procexp","xenos","xenos64","gh injector","guidedhacking",
    # Generic cheat features
    "autoclick","clicker","aimassist","triggerbot","esp","reach","bhop","keystrokes"
)

# Suspicious install locations (user-writable)
$SuspiciousRoots = @(
    [IO.Path]::GetTempPath().TrimEnd('\'),
    "$env:USERPROFILE\Downloads",
    "$env:USERPROFILE\Desktop",
    "$env:APPDATA",
    "$env:LOCALAPPDATA"
) | Where-Object { $_ -and (Test-Path $_) }

# Known-safe roots (Windows + Java)
$SafeRoots = @()
$SafeRoots += $env:SystemRoot, "$($env:SystemRoot)\System32", "$($env:SystemRoot)\SysWOW64"
$SafeRoots += $env:ProgramFiles, $env:"ProgramFiles(x86)"
# Java homes (Registry + env)
try {
    $javaHomes = @()
    if ($env:JAVA_HOME) { $javaHomes += $env:JAVA_HOME }
    $jreKey = "HKLM:\SOFTWARE\JavaSoft\Java Runtime Environment"
    if (Test-Path $jreKey) {
        Get-ChildItem $jreKey | ForEach-Object {
            $jp = (Get-ItemProperty $_.PsPath)."JavaHome"
            if ($jp) { $javaHomes += $jp }
        }
    }
    $javaHomes | Where-Object { $_ -and (Test-Path $_) } | ForEach-Object { $SafeRoots += $_ }
} catch {}

$SafeRoots = $SafeRoots | ForEach-Object { if ($_ -is [string]) { $_.TrimEnd('\') } } | Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique

# Known injector processes (lowercase)
$InjectorProcs = @(
    "cheatengine","processhacker","procexp","xenos","xenos64","gh injector","extremeinjector",
    "sharpinjector","dllinjector","hollowsheaven","guidedhacking"
)

#endregion

#region --- Find Minecraft process ---
Write-Host "Searching for Minecraft process (javaw.exe)..." -ForegroundColor Cyan
$mc = Get-Process -Name "javaw" -ErrorAction SilentlyContinue | Sort-Object StartTime -Descending | Select-Object -First 1
if (-not $mc) {
    Write-Host "[!] Minecraft (javaw.exe) not running. Start the game first." -ForegroundColor Red
    Read-Host "Press ENTER to exit"
    exit 1
}
Write-Host "[+] Found javaw.exe  PID=$($mc.Id)  Started=$($mc.StartTime)" -ForegroundColor Green
#endregion

#region --- Progress scaffolding ---
$steps = @(
    "Enumerating loaded modules",
    "Hashing DLLs",
    "Applying heuristic checks (paths/keywords)",
    "Scanning for injector processes",
    "Writing reports"
)
function Step($idx,$msg) {
    $percent = [int](($idx / ($steps.Count)) * 100)
    Write-Progress -Activity "InjectedHackHunter1" -Status $msg -PercentComplete $percent
}
#endregion

#region --- Module enumeration ---
Step 1 $steps[0]
$modules = $null
try {
    $modules = (Get-Process -Id $mc.Id -Module -ErrorAction Stop) | Select-Object ModuleName, FileName
} catch {
    try {
        $p = [System.Diagnostics.Process]::GetProcessById($mc.Id)
        $modules = $p.Modules | ForEach-Object {
            [pscustomobject]@{ ModuleName = $_.ModuleName; FileName = $_.FileName }
        }
    } catch {
        Write-Host "[x] Unable to enumerate modules from javaw.exe. Try 64-bit PowerShell as Admin." -ForegroundColor Red
        Read-Host "Press ENTER to exit"
        exit 2
    }
}
#endregion

#region --- Hash + Heuristics ---
Step 2 $steps[1]
$rows = New-Object System.Collections.Generic.List[object]
$hitsKnown = 0; $hitsWarn = 0; $hitsOk = 0

function InRoots($path, [string[]]$roots) {
    if (-not $path) { return $false }
    $norm = (Resolve-Path -LiteralPath $path -ErrorAction SilentlyContinue)?.Path
    if (-not $norm) { return $false }
    foreach ($r in $roots) {
        try {
            $rn = (Resolve-Path -LiteralPath $r -ErrorAction SilentlyContinue)?.Path
            if ($rn -and $norm.StartsWith($rn, [StringComparison]::InvariantCultureIgnoreCase)) { return $true }
        } catch {}
    }
    return $false
}

function Read-HeadAscii($file, $max=2097152) {
    try {
        $fs = [IO.File]::Open($file, 'Open', 'Read', 'ReadWrite')
        try {
            $len = [math]::Min($max, $fs.Length)
            $buf = New-Object byte[] $len
            [void]$fs.Read($buf,0,$len)
            return [Text.Encoding]::ASCII.GetString($buf)
        } finally { $fs.Close() }
    } catch { return "" }
}

Write-Host "`n[i] Scanning loaded DLLs in javaw.exe ..." -ForegroundColor Yellow
$idx = 0
foreach ($m in $modules) {
    $idx++
    Write-Progress -Activity "InjectedHackHunter1" -Status "Scanning module $idx / $($modules.Count)" -PercentComplete ([int](($idx/$modules.Count)*100))

    $name = $m.ModuleName
    $path = $m.FileName
    $hash = if ($path -and (Test-Path -LiteralPath $path)) { Sha256 $path } else { $null }

    $status = "LIKELY_SAFE"
    $reasons = New-Object System.Collections.Generic.List[string]

    if ($hash -and ($KnownHackHashes -contains $hash.ToUpperInvariant())) {
        $status = "KNOWN_HACK"; $reasons.Add("DLL SHA-256 matches known hack list")
    }

    if ($status -eq "LIKELY_SAFE") {
        if (InRoots $path $SuspiciousRoots) {
            $status = "SUSPICIOUS"; $reasons.Add("Loaded from user-writable path")
        }
    }

    if ($status -eq "LIKELY_SAFE") {
        if (-not (InRoots $path $SafeRoots)) {
            $status = "SUSPICIOUS"; $reasons.Add("Not in known safe root (Windows/Java)")
        }
    }

    if ($status -ne "KNOWN_HACK") {
        $blob = Read-HeadAscii $path 1048576
        foreach ($kw in $KeywordHints) {
            if (($name -and ($name -like "*$kw*")) -or ($path -and ($path -like "*$kw*")) -or ($blob.IndexOf($kw,[StringComparison]::OrdinalIgnoreCase) -ge 0)) {
                if ($status -eq "LIKELY_SAFE") { $status = "SUSPICIOUS" }
                $reasons.Add("Contains hint: $kw")
                break
            }
        }
    }

    switch ($status) {
        "KNOWN_HACK" { $hitsKnown++ ; Write-Host "[HACK] $name  -> $(Shorten $path)" -ForegroundColor Red }
        "SUSPICIOUS" { $hitsWarn++  ; Write-Host "[WARN] $name  -> $(Shorten $path)" -ForegroundColor Yellow }
        default      { $hitsOk++    ; Write-Host "[OK]   $name  -> $(Shorten $path)" -ForegroundColor Green }
    }
    if ($reasons.Count -gt 0) { Write-Host "       Reasons: " ($reasons -join "; ") -ForegroundColor DarkGray }

    $rows.Add([pscustomobject]@{
        Status  = $status
        Module  = $name
        Path    = $path
        SHA256  = $hash
        Reasons = ($reasons -join "; ")
    })
}
#endregion

#region --- Injector process scan ---
Step 3 $steps[3]
Write-Host "`n[i] Scanning for injector/helper processes..." -ForegroundColor Cyan
$procs = Get-Process | Sort-Object ProcessName | ForEach-Object {
    [pscustomobject]@{ Name = $_.ProcessName.ToLower(); Id = $_.Id }
}
$inj = @()
foreach ($p in $procs) {
    foreach ($k in $InjectorProcs) {
        if ($p.Name -like "*$k*") {
            $inj += $p
            Write-Host "[INJECTOR] $($p.Name)  PID=$($p.Id)" -ForegroundColor Magenta
            break
        }
    }
}
#endregion

#region --- Reports ---
Step 4 $steps[4]
$desktop = [Environment]::GetFolderPath('Desktop')
$stamp = NowStamp
$txt = Join-Path $desktop "InjectedHackHunter1_Report_$stamp.txt"
$csv = Join-Path $desktop "InjectedHackHunter1_Report_$stamp.csv"

"InjectedHackHunter1 Report  (Generated: $(Get-Date))" | Out-File -FilePath $txt -Encoding UTF8
"Target: javaw.exe  PID=$($mc.Id)  Start=$($mc.StartTime)" | Out-File -FilePath $txt -Append -Encoding UTF8
"------------------------------------------------------------" | Out-File -FilePath $txt -Append -Encoding UTF8
$rows | ForEach-Object {
    $line = "{0,-12} {1,-28} {2}" -f $_.Status, $_.Module, (Shorten $_.Path)
    $line | Out-File -FilePath $txt -Append -Encoding UTF8
    if ($_.Reasons) { ("    Reasons: " + $_.Reasons) | Out-File -FilePath $txt -Append -Encoding UTF8 }
}
"------------------------------------------------------------" | Out-File -FilePath $txt -Append -Encoding UTF8
"Totals: HACK=$hitsKnown  WARN=$hitsWarn  OK=$hitsOk  INJECTOR=$($inj.Count)" | Out-File -FilePath $txt -Append -Encoding UTF8

$rows | Export-Csv -Path $csv -NoTypeInformation -Encoding UTF8

Write-Host "`n[✓] Reports saved:" -ForegroundColor Cyan
Write-Host "    TXT: $txt"
Write-Host "    CSV: $csv"
Write-Host "`nSummary: HACK=$hitsKnown | WARN=$hitsWarn | OK=$hitsOk | INJECTOR=$($inj.Count)" -ForegroundColor Cyan

Read-Host "`nDone. Press ENTER to exit"
#endregion

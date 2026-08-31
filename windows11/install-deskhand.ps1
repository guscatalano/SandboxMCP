<#
    Install Deskhand's HTTP server into a sandbox VM and start it at logon.

    Runs inside the guest, from an attached payload CD built by push-deskhand.sh:
        powershell -ExecutionPolicy Bypass -File D:\install-deskhand.ps1 `
            -Token <token> -AutoLogonUser sandbox -AutoLogonPassword <pw>

    Why this shape:

    * Bound to the machine's own IPv4, not 'any'. The sandbox has one NIC so they
      are equivalent today, but naming the address means a second NIC never
      silently starts answering. Deskhand REFUSES to start on a non-loopback bind
      without DESKHAND_TOKEN, so the token is mandatory, not advisory.

    * A logon scheduled task, not a service. Deskhand drives the desktop through
      UI Automation, which only works inside an interactive session -- a service
      in session 0 has no desktop to automate.

    * The address is resolved at launch rather than baked in, so the same payload
      works in any clone whatever DHCP lease it gets.
#>
param(
    [Parameter(Mandatory)][string]$Token,
    [int]$Port = 8791,
    [string]$InstallDir = 'C:\Deskhand',
    [string]$AutoLogonUser = '',
    [string]$AutoLogonPassword = '',
    # Deskhand's command runner is off unless this is set. It runs arbitrary
    # code as the logged-in user, so it is opt-in upstream -- on a disposable
    # sandbox that is exactly what you want, hence default on here.
    [switch]$NoShell,
    # DESKHAND_TLS=self-signed makes Deskhand generate its own certificate at
    # startup (SANs cover localhost and the box's IPv4s). Without it the bearer
    # token crosses the network in clear text. The cert is EPHEMERAL -- a fresh
    # one each start -- so browsers warn and the fingerprint changes on reboot.
    # For anything beyond a lab, front it with a real cert via DESKHAND_TLS_CERT.
    [switch]$NoTls
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
function Step($m) { Write-Host "`n=== $m ===" -ForegroundColor Cyan }
function Ok($m)   { Write-Host "  [ok]   $m" }
function Warn($m) { Write-Host "  [warn] $m" -ForegroundColor Yellow }

# ---------------------------------------------------------------------------
Step 'Locate payload'
# By content, not drive letter -- letters shift between boots.
$src = Get-Volume | Where-Object DriveLetter |
    ForEach-Object { "$($_.DriveLetter):" } |
    Where-Object { Test-Path (Join-Path $_ 'deskhand.zip') } |
    Select-Object -First 1
if (-not $src) { throw 'deskhand.zip not found on any attached volume' }
Ok "payload at $src"

Step 'Extract'
if (Test-Path $InstallDir) { Remove-Item $InstallDir -Recurse -Force }
Expand-Archive -Path (Join-Path $src 'deskhand.zip') -DestinationPath $InstallDir -Force
$exe = Join-Path $InstallDir 'deskhand-http.exe'
if (-not (Test-Path $exe)) { throw "deskhand-http.exe missing from $InstallDir" }
Ok "$InstallDir ($([int]((Get-ChildItem $InstallDir -Recurse | Measure-Object Length -Sum).Sum/1MB)) MB)"

# ---------------------------------------------------------------------------
Step 'Write launcher'
$runner = Join-Path $InstallDir 'run-deskhand.ps1'
$shellLine = if (-not $NoShell) { "`$env:DESKHAND_ENABLE_SHELL = '1'" } else { '' }
$tlsLine   = if (-not $NoTls)   { "`$env:DESKHAND_TLS = 'self-signed'" } else { '' }
@"
`$ip = (Get-NetIPAddress -AddressFamily IPv4 |
        Where-Object { `$_.IPAddress -notlike '127.*' -and `$_.IPAddress -notlike '169.254.*' } |
        Select-Object -First 1).IPAddress
if (-not `$ip) { `$ip = 'any' }
`$env:DESKHAND_BIND  = `$ip
`$env:DESKHAND_TOKEN = '$Token'
`$env:DESKHAND_PORT  = '$Port'
$shellLine
$tlsLine
Set-Location '$InstallDir'
& '$exe'
"@ | Set-Content $runner -Encoding UTF8
Ok $runner

# ---------------------------------------------------------------------------
Step 'Firewall'
Remove-NetFirewallRule -DisplayName 'Deskhand HTTP' -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName 'Deskhand HTTP' -Direction Inbound -Action Allow `
    -Protocol TCP -LocalPort $Port -Profile Any | Out-Null
Ok "inbound tcp/$Port allowed"

# ---------------------------------------------------------------------------
Step 'Register logon task'
# The ScheduledTasks cmdlets, deliberately not schtasks.exe. Piping a native
# command's stderr (`schtasks /Delete ... 2>&1 | Out-Null`) under
# $ErrorActionPreference='Stop' throws a NativeCommandError when the task does
# not exist yet -- which killed this script mid-run the first time. These
# cmdlets also avoid quoting the /TR argument, which is its own minefield.
$user = if ($AutoLogonUser) { $AutoLogonUser } else { $env:USERNAME }
$action  = New-ScheduledTaskAction -Execute 'powershell.exe' `
    -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$runner`""
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $user
# LogonType Interactive + RunLevel Limited: it must land in the user's desktop
# session, and per Deskhand's own design it runs unelevated.
$principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Limited
Register-ScheduledTask -TaskName 'Deskhand' -Action $action -Trigger $trigger `
    -Principal $principal -Force | Out-Null
Ok "task 'Deskhand' -> $((Get-ScheduledTask -TaskName Deskhand).State), runs at logon as $user"

# ---------------------------------------------------------------------------
if ($AutoLogonUser -and $AutoLogonPassword) {
    Step 'Auto-logon (applied at boot, not here)'
    # Auto-logon CANNOT be declared in the sysprep answer file. OOBE creates a
    # temporary 'defaultuser0', points AutoAdminLogon at it, and then hangs
    # trying to log in as that disabled account -- and wipes AutoAdminLogon and
    # DefaultUserName during its cleanup. Writing the values here does not help
    # either: this runs before OOBE on a clone, so they get erased too.
    #
    # So a startup task applies them once OOBE has genuinely finished, then
    # reboots exactly once. It is idempotent: on every later boot the values are
    # already correct, so it does nothing and there is no reboot loop.
    #
    # The password lands in the registry in CLEAR TEXT -- that is how Windows
    # auto-logon works, and it is why this belongs only on a disposable VM.
    $fixer = Join-Path $InstallDir 'apply-autologon.ps1'
    @"
`$wl = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
# SystemSetupInProgress stays 1 until OOBE is completely done.
while ((Get-ItemProperty 'HKLM:\SYSTEM\Setup' -ErrorAction SilentlyContinue).SystemSetupInProgress -ne 0) {
    Start-Sleep -Seconds 5
}
Start-Sleep -Seconds 25   # let OOBE's own Winlogon cleanup settle first
`$p = Get-ItemProperty `$wl -ErrorAction SilentlyContinue
if (`$p.AutoAdminLogon -ne '1' -or `$p.DefaultUserName -ne '$AutoLogonUser') {
    Set-ItemProperty `$wl -Name AutoAdminLogon    -Value '1' -Type String
    Set-ItemProperty `$wl -Name DefaultUserName   -Value '$AutoLogonUser' -Type String
    Set-ItemProperty `$wl -Name DefaultPassword   -Value '$AutoLogonPassword' -Type String
    Set-ItemProperty `$wl -Name DefaultDomainName -Value `$env:COMPUTERNAME -Type String
    Restart-Computer -Force
}
"@ | Set-Content $fixer -Encoding UTF8

    $fa = New-ScheduledTaskAction -Execute 'powershell.exe' `
        -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$fixer`""
    $ft = New-ScheduledTaskTrigger -AtStartup
    $fp = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName 'DeskhandAutoLogon' -Action $fa -Trigger $ft `
        -Principal $fp -Force | Out-Null
    Ok "startup task 'DeskhandAutoLogon' will enable auto-logon as $AutoLogonUser after OOBE"
} else {
    Warn 'auto-logon not configured; Deskhand starts only once someone logs in'
}

Step 'Done'
Write-Host @"
  Deskhand installed to $InstallDir, listening on this machine's IPv4 : $Port
  Reboot to bring it up:  shutdown /r /t 0
  Then from your LAN:     curl -k -H "Authorization: Bearer <token>" $(if ($NoTls) {"http"} else {"https"})://<ip>:$Port/machine
"@

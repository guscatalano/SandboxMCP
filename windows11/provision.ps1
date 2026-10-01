<#
    First-boot provisioning, run once by autounattend.xml's FirstLogonCommands.
    Output is appended to C:\Windows\Temp\provision.log -- read that first when a
    build comes up wrong.

    Everything here is idempotent, so it is safe to re-run by hand:
        powershell -ExecutionPolicy Bypass -File D:\provision.ps1

    Deliberately no network dependency for the essential steps. The VirtIO
    network driver is one of the things being installed, so anything that needed
    the network to install the network would be a bootstrap problem. Optional
    winget packages run last and are allowed to fail.
#>

$ErrorActionPreference = 'Continue'   # one bad step must not abort the rest
$ProgressPreference    = 'SilentlyContinue'   # progress bars are very slow over a serial-ish console

function Step($name) { Write-Host "`n=== $name ===" -ForegroundColor Cyan }
function Ok($m)      { Write-Host "  [ok]   $m" }
function Warn($m)    { Write-Host "  [warn] $m" -ForegroundColor Yellow }

Write-Host "provision.ps1 starting $(Get-Date -Format s) on $env:COMPUTERNAME"

# ---------------------------------------------------------------------------
# Device encryption
# ---------------------------------------------------------------------------
# Windows 11 24H2+ silently switches on device encryption during OOBE whenever
# the machine has a TPM and Secure Boot -- which every VM from create-vm.sh has
# by design. Sensible on a laptop, wrong for a template: sysprep refuses to
# generalize an encrypted OS volume (0x80310039), so make-template.sh would die
# at the very end of a 25-minute build. Turn it off now, first thing, and set
# the policy so it cannot come back.
Step 'Device encryption'
reg add HKLM\SYSTEM\CurrentControlSet\Control\BitLocker /v PreventDeviceEncryption /t REG_DWORD /d 1 /f 2>&1 | Out-Null
$bl = Get-BitLockerVolume -MountPoint C: -ErrorAction SilentlyContinue
if ($bl -and $bl.VolumeStatus -ne 'FullyDecrypted') {
    manage-bde -off C: 2>&1 | Out-Null
    Warn "was $($bl.VolumeStatus); decryption started and continues in background"
} else {
    Ok 'not encrypted'
}

# ---------------------------------------------------------------------------
# Windows Update during OOBE
# ---------------------------------------------------------------------------
# OOBE contacts Windows Update and installs a "zero-day patch" before the
# desktop appears. The ZDP requires a reboot, and the OOBE pass that runs after
# that reboot CLEARS the auto-logon values -- so a controller that wrote them
# before the reboot finds them gone, the sandbox comes up with no session, and
# the Deskhand install fails into "Why did my PC restart?".
#
# <ProtectYourPC>3</ProtectYourPC> in the answer file does NOT prevent this; it
# governs the privacy settings page, not the ZDP fetch. This policy does, and it
# lives in the Policies hive, which survives sysprep /generalize.
#
# A template is a base image, not a machine anyone browses from: it should be
# patched deliberately by rebuilding it, never by OOBE behind your back.
Step 'Windows Update during OOBE'
$wu = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
reg add $wu /v DoNotConnectToWindowsUpdateInternetLocations /t REG_DWORD /d 1 /f 2>&1 | Out-Null
reg add "$wu\AU" /v NoAutoUpdate /t REG_DWORD /d 1 /f 2>&1 | Out-Null
Ok 'ZDP disabled'

# ---------------------------------------------------------------------------
# Clock
# ---------------------------------------------------------------------------
# A sandbox with a wrong clock timestamps every log, file and recording wrongly,
# which makes correlating them with the host useless. Measured on this fleet
# before this existed: every clone exactly 7 hours behind, for the sandbox's
# whole life.
#
# The VM must also be created with localtime=0 (sandboxctl does this): Proxmox
# starts QEMU with -rtc base=localtime for win11, and a UTC guest then reads the
# host's local time as UTC. This section is the in-guest half.
Step 'Clock'

# UTC throughout, so "local time" and UTC are the same thing and the RTC base
# cannot be misread.
tzutil /s 'UTC' 2>&1 | Out-Null

# The hardware clock holds UTC. Honoured when Windows reads the RTC; NOT when it
# writes it, so this is a nicety and the resync task below is the guarantee.
reg add 'HKLM\SYSTEM\CurrentControlSet\Control\TimeZoneInformation' `
    /v RealTimeIsUniversal /t REG_DWORD /d 1 /f 2>&1 | Out-Null

# The Hyper-V integration time provider is present in this image and enabled,
# but it syncs from a Hyper-V host and there is none under KVM. Disable it so
# w32time does not weigh a dead source.
reg add 'HKLM\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\VMICTimeProvider' `
    /v Enabled /t REG_DWORD /d 0 /f 2>&1 | Out-Null

# Permit a correction of any size. The default caps it at 54000 s, and the error
# this fixes was 25200 s with a cold clock able to be worse.
reg add 'HKLM\SYSTEM\CurrentControlSet\Services\W32Time\Config' `
    /v MaxPosPhaseCorrection /t REG_DWORD /d 0xFFFFFFFF /f 2>&1 | Out-Null
reg add 'HKLM\SYSTEM\CurrentControlSet\Services\W32Time\Config' `
    /v MaxNegPhaseCorrection /t REG_DWORD /d 0xFFFFFFFF /f 2>&1 | Out-Null
reg add 'HKLM\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\NtpClient' `
    /v SpecialPollInterval /t REG_DWORD /d 900 /f 2>&1 | Out-Null

# w32time is trigger-started and stops itself when Windows thinks it is idle,
# which on a non-domain machine is most of the time.
sc.exe triggerinfo w32time delete 2>&1 | Out-Null
sc.exe config w32time start= auto 2>&1 | Out-Null

# A sandbox reaches the internet but not a domain, so public NTP it is. 0x9 is
# client mode plus "honour SpecialPollInterval".
w32tm /config /manualpeerlist:'time.cloudflare.com,0x9 time.google.com,0x9 pool.ntp.org,0x9' `
      /syncfromflags:MANUAL /update 2>&1 | Out-Null

# The safety net. w32time will not correct a large error on its own -- it keeps
# reporting "Local CMOS Clock" and leaves the clock wrong -- so force it at every
# boot, several times, because the network may not be up on the first attempt.
$resync = 'Start-Service w32time; Start-Sleep 15; foreach($i in 1..6){ & w32tm /resync /force; Start-Sleep 10 }'
$rAction = New-ScheduledTaskAction -Execute 'powershell.exe' `
    -Argument ('-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -Command "' + $resync + '"')
$rPrincipal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$rSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
Register-ScheduledTask -TaskName 'SandboxTimeResync' -Force `
    -Action $rAction -Trigger (New-ScheduledTaskTrigger -AtStartup) `
    -Principal $rPrincipal -Settings $rSettings | Out-Null
Ok 'UTC, NTP peers set, resync at boot'

# ---------------------------------------------------------------------------
# Groundhog agent
# ---------------------------------------------------------------------------
# Groundhog configures a Windows machine from a declarative file. Its templated-VM
# design is exactly this shape: install the agent once in the image with a logon
# task, and a host then only has to drop %ProgramData%\groundhog\pending.json --
# which the QEMU guest agent can do before Deskhand even exists. Costs ~1.8 MB and
# nothing at runtime: run-pending is a no-op when that file is absent.
#
# The task is registered here with schtasks rather than `groundhog-agent
# install-task`, because install-task takes the task's user from the CURRENT
# process. During a template build that is SYSTEM, which would register a task
# that never fires for the interactive user. These are install-task's own switches.
Step 'Groundhog agent'
$ghHome = Join-Path $env:ProgramData 'groundhog'
$ghBin  = Join-Path $ghHome 'bin'
New-Item -ItemType Directory -Force -Path $ghBin | Out-Null
$ghExe  = Join-Path $ghBin 'groundhog-agent.exe'
try {
    $rel = Invoke-RestMethod -Uri 'https://api.github.com/repos/guscatalano/Groundhog/releases/latest' `
                             -Headers @{ 'User-Agent' = 'sandboxctl' } -TimeoutSec 60
    $asset = $rel.assets | Where-Object { $_.name -eq 'groundhog-agent-x64.exe' } | Select-Object -First 1
    Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $ghExe -UseBasicParsing -TimeoutSec 180
    $action = '"' + $ghExe + '" run-pending'
    schtasks.exe /Create /F /TN 'Groundhog\RunPending' /SC ONLOGON /RL HIGHEST /IT `
                 /DELAY 0000:15 /RU '@@USERNAME@@' /TR $action 2>&1 | Out-Null
    Ok "$($rel.tag_name), logon task registered"
} catch {
    Warn "not installed: $($_.Exception.Message)"
}

# ---------------------------------------------------------------------------
# Locate the virtio-win CD
# ---------------------------------------------------------------------------
# Identified by content rather than by drive letter or volume label, because
# both vary between virtio-win releases and between VMs.
Step 'Locate virtio-win media'
$virtio = Get-Volume |
    Where-Object { $_.DriveLetter } |
    ForEach-Object { "$($_.DriveLetter):" } |
    Where-Object { Test-Path (Join-Path $_ 'virtio-win-gt-x64.msi') } |
    Select-Object -First 1

if ($virtio) { Ok "found at $virtio" } else { Warn 'virtio-win CD not found -- driver and guest-agent install will be skipped' }

# ---------------------------------------------------------------------------
# VirtIO drivers + QEMU guest agent
# ---------------------------------------------------------------------------
# The guest agent is what lets Proxmox report the guest IP, quiesce filesystems
# for a consistent snapshot, and shut the VM down cleanly instead of pulling the
# virtual power cord. Without it `qm shutdown` is a hope, not an instruction.
if ($virtio) {
    Step 'Install VirtIO drivers'
    $msi = Join-Path $virtio 'virtio-win-gt-x64.msi'
    $p = Start-Process msiexec.exe -Wait -PassThru -ArgumentList @(
        '/i', "`"$msi`"", '/qn', '/norestart', 'ADDLOCAL=ALL'
    )
    if ($p.ExitCode -in 0, 3010) { Ok "virtio-win-gt-x64.msi exit $($p.ExitCode)" }
    else                         { Warn "virtio-win-gt-x64.msi exit $($p.ExitCode)" }

    Step 'Install QEMU guest agent'
    # Path moved between virtio-win releases; try both known layouts.
    $ga = @(
        (Join-Path $virtio 'guest-agent\qemu-ga-x86_64.msi'),
        (Join-Path $virtio 'guest-agent\qemu-ga-x64.msi')
    ) | Where-Object { Test-Path $_ } | Select-Object -First 1

    if ($ga) {
        $p = Start-Process msiexec.exe -Wait -PassThru -ArgumentList @('/i', "`"$ga`"", '/qn', '/norestart')
        if ($p.ExitCode -in 0, 3010) { Ok "guest agent installed (exit $($p.ExitCode))" }
        else                         { Warn "guest agent exit $($p.ExitCode)" }
        Start-Service QEMU-GA -ErrorAction SilentlyContinue
        Set-Service  QEMU-GA -StartupType Automatic -ErrorAction SilentlyContinue
    } else {
        Warn 'qemu-ga MSI not found on virtio media'
    }
}

# ---------------------------------------------------------------------------
# Power behaviour
# ---------------------------------------------------------------------------
# A server that sleeps is a server that is down. Hibernation off also reclaims
# hiberfil.sys, which is sized at a fraction of RAM and is pure waste in a VM
# whose "resume" story is `qm start`.
Step 'Power settings'
powercfg /setactive SCHEME_MIN            2>&1 | Out-Null   # High performance
powercfg /change standby-timeout-ac 0     2>&1 | Out-Null
powercfg /change monitor-timeout-ac  0    2>&1 | Out-Null
powercfg /change disk-timeout-ac     0    2>&1 | Out-Null
powercfg /hibernate off                   2>&1 | Out-Null
Ok 'never sleeps, hibernation disabled'

# ---------------------------------------------------------------------------
# Remote access
# ---------------------------------------------------------------------------
# autounattend.xml already set these; repeated here so that re-running this
# script by hand fully restores remote access on a machine somebody locked down.
Step 'Remote Desktop'
Set-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value 0
Set-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -Value 1
Enable-NetFirewallRule -DisplayGroup 'Remote Desktop' -ErrorAction SilentlyContinue
Ok 'RDP enabled with NLA'

# ---------------------------------------------------------------------------
# Make the LAN a private network
# ---------------------------------------------------------------------------
# Windows defaults an unidentified network to Public, which blocks file sharing
# and ICMP. On a lab LAN that mostly means "ping does not work and nobody knows
# why". Only interfaces that are actually up are touched.
Step 'Network profile'
Get-NetConnectionProfile -ErrorAction SilentlyContinue |
    Where-Object NetworkCategory -eq 'Public' |
    ForEach-Object {
        Set-NetConnectionProfile -InterfaceIndex $_.InterfaceIndex -NetworkCategory Private
        Ok "interface $($_.InterfaceIndex) -> Private"
    }

# ---------------------------------------------------------------------------
# Trim consumer cruft
# ---------------------------------------------------------------------------
# Policy keys only -- no app removal, no service disabling. These are documented
# settings that survive feature updates. Aggressive "debloat" scripts break
# Windows Update in ways that surface months later.
Step 'Disable consumer features'
$policies = @{
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' = @{
        DisableWindowsConsumerFeatures = 1   # no auto-installed suggested apps
        DisableConsumerAccountStateContent = 1
    }
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OOBE' = @{
        DisablePrivacyExperience = 1         # no privacy wizard after updates
    }
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' = @{
        AllowTelemetry = 1                   # Required diagnostic data only
    }
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' = @{
        DisableSearchBoxSuggestions = 1
    }
}
foreach ($path in $policies.Keys) {
    if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
    foreach ($name in $policies[$path].Keys) {
        New-ItemProperty -Path $path -Name $name -Value $policies[$path][$name] `
                         -PropertyType DWord -Force | Out-Null
    }
    Ok (Split-Path $path -Leaf)
}

# Show file extensions -- hiding them is a security footgun, not a convenience.
$adv = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
Set-ItemProperty $adv -Name HideFileExt -Value 0 -ErrorAction SilentlyContinue
Ok 'file extensions visible'

# ---------------------------------------------------------------------------
# Optional packages
# ---------------------------------------------------------------------------
# Last, and allowed to fail. winget on fresh media often needs a Store update
# before it works, and this whole script runs before any network guarantee.
# A failure here leaves a perfectly good machine; installing apps by hand later
# is a minor annoyance, whereas aborting the script would skip nothing important
# because everything important already ran above.
Step 'Optional packages (winget)'
$packages = @(
@@WINGET_PACKAGES@@
)

if ($packages.Count -eq 0) {
    Ok 'none requested'
} elseif (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
    Warn 'winget not available yet -- install these by hand later:'
    $packages | ForEach-Object { Warn "    $_" }
} else {
    foreach ($pkg in $packages) {
        Write-Host "  installing $pkg ..."
        winget install --id $pkg --exact --silent --accept-package-agreements `
                       --accept-source-agreements --disable-interactivity 2>&1 |
            Out-String | Write-Host
        if ($LASTEXITCODE -eq 0) { Ok $pkg } else { Warn "$pkg (exit $LASTEXITCODE)" }
    }
}

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
# The marker file is how you tell "provisioning ran and finished" apart from
# "provisioning never started" without reading the whole log.
Step 'Complete'
$marker = 'C:\Windows\Temp\provision-complete.txt'
"provisioned $(Get-Date -Format s) by provision.ps1" | Set-Content $marker
Ok "marker written to $marker"
Write-Host "`nA reboot is required for the VirtIO drivers to be fully active."

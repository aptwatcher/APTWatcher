<#
.SYNOPSIS
    Autonomous in-VM deployment test for APTWatcher.

.DESCRIPTION
    Orchestrates a hands-off deployment test inside the SIFT VM: starts the
    VM headless, waits for the guest to become reachable, delivers the
    APTWatcher source (git clone or local copy), runs the already-validated
    provisioning + gate scripts inside the guest, collects the result, and
    powers the VM back off.

    This script is deliberately thin: all the real work happens in
    scripts/prepare-vm.sh and scripts/run-gates.sh inside the guest. Here we
    only own the VM lifecycle and the remote-exec plumbing.

    Host language is PowerShell because the host is Windows and Hyper-V has
    no usable CLI outside it; VMware (vmrun/ovftool) and VirtualBox
    (VBoxManage) are driven through their .exe CLIs from the same script.

    SECURITY: no credentials are baked into this file. Supply them at call
    time via parameters or the APTW_GUEST_* environment variables. Prefer an
    SSH key over a password. Never commit a populated credential.

.PARAMETER Hypervisor
    auto | vmware | hyperv | virtualbox. 'auto' probes for an available CLI.

.PARAMETER Exec
    auto | ssh | guest. How to run commands in the guest. 'ssh' is portable
    and the only option for a Linux guest under Hyper-V (PowerShell Direct
    targets Windows guests only). 'guest' uses VBoxManage/vmrun guest-control.

.PARAMETER Source
    git | local. Deliver the repo by cloning from GitHub (tests the public
    deployment path) or by copying the local working tree (tests un-pushed
    changes).

.EXAMPLE
    # VMware + SSH (key auth) + git clone, fully autonomous:
    .\scripts\vm-test.ps1 -Hypervisor vmware -Vmx 'C:\Users\me\Dev\APTWatcher\vm\sift.vmx' `
        -Exec ssh -GuestUser sansforensics -GuestKey $HOME\.ssh\sift_id_ed25519 -Source git

.EXAMPLE
    # Hyper-V + SSH + local copy, keep VM running for inspection on failure:
    .\scripts\vm-test.ps1 -Hypervisor hyperv -VmName 'SIFT' -Exec ssh `
        -GuestUser sansforensics -GuestKey $HOME\.ssh\sift_id_ed25519 -Source local -KeepRunning

.EXAMPLE
    # VirtualBox + guest-control (no SSH needed), password from env var:
    $env:APTW_GUEST_PASSWORD = (Read-Host -AsSecureString | ConvertFrom-SecureString -AsPlainText)
    .\scripts\vm-test.ps1 -Hypervisor virtualbox -VmName 'SIFT' -Exec guest -GuestUser sansforensics
#>

[CmdletBinding()]
param(
    [ValidateSet('auto','vmware','hyperv','virtualbox')] [string] $Hypervisor = 'auto',
    [ValidateSet('auto','ssh','guest')]                  [string] $Exec       = 'auto',
    [ValidateSet('git','local')]                         [string] $Source     = 'git',

    # VM identity (supply what matches your hypervisor)
    [string] $VmName = $env:APTW_VM_NAME,            # Hyper-V / VirtualBox registered name
    [string] $Vmx    = $env:APTW_VMX,               # VMware .vmx path

    # Code delivery
    [string] $RepoUrl   = 'https://github.com/aptwatcher/APTWatcher.git',
    [string] $LocalRepo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path,
    [string] $TargetDir = '~/APTWatcher',

    # Guest access
    [string] $GuestUser     = $env:APTW_GUEST_USER,
    [string] $GuestHost     = $env:APTW_GUEST_HOST, # SSH target; auto-resolved if empty
    [string] $GuestKey      = $env:APTW_GUEST_KEY,  # SSH private key path
    [string] $GuestPassword = $env:APTW_GUEST_PASSWORD, # guest-control only

    # Behaviour
    [int]    $BootTimeoutSec = 300,
    [switch] $Fast,          # pass --fast to run-gates.sh
    [switch] $KeepRunning    # do not power off at the end (handy on failure)
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
function _ts { (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }
function Log  ($m) { Write-Host  ("{0} [INFO] {1}" -f (_ts), $m) -ForegroundColor Cyan }
function Ok   ($m) { Write-Host  ("{0} [ OK ] {1}" -f (_ts), $m) -ForegroundColor Green }
function Warn ($m) { Write-Warning ("{0} {1}" -f (_ts), $m) }
function Die  ($m) { Write-Error  ("{0} [FAIL] {1}" -f (_ts), $m); exit 2 }

function Require-Cmd ($name) {
    if (-not (Get-Command $name -ErrorAction SilentlyContinue)) {
        Die "required command not found on PATH: $name"
    }
}

# ---------------------------------------------------------------------------
# Hypervisor detection
# ---------------------------------------------------------------------------
function Resolve-Hypervisor {
    if ($Hypervisor -ne 'auto') { return $Hypervisor }
    if (Get-Command VBoxManage -ErrorAction SilentlyContinue) { return 'virtualbox' }
    if (Get-Command vmrun      -ErrorAction SilentlyContinue) { return 'vmware' }
    if (Get-Command Get-VM     -ErrorAction SilentlyContinue) { return 'hyperv' }
    Die "could not auto-detect a hypervisor (no VBoxManage / vmrun / Hyper-V module). Pass -Hypervisor explicitly."
}

function Resolve-Exec ($hv) {
    if ($Exec -ne 'auto') { return $Exec }
    # Hyper-V Linux guests have no guest-control; default to SSH everywhere.
    return 'ssh'
}

# ---------------------------------------------------------------------------
# VM lifecycle (per backend)
# ---------------------------------------------------------------------------
function Start-Vm ($hv) {
    switch ($hv) {
        'virtualbox' {
            if (-not $VmName) { Die "VirtualBox needs -VmName (registered VM name)." }
            Log "starting VirtualBox VM '$VmName' (headless)"
            & VBoxManage startvm $VmName --type headless | Out-Host
        }
        'vmware' {
            if (-not $Vmx) { Die "VMware needs -Vmx (path to the .vmx)." }
            Log "starting VMware VM '$Vmx' (nogui)"
            & vmrun start $Vmx nogui | Out-Host
        }
        'hyperv' {
            if (-not $VmName) { Die "Hyper-V needs -VmName." }
            Log "starting Hyper-V VM '$VmName'"
            Start-VM -Name $VmName | Out-Null
        }
    }
    Ok "VM start issued"
}

function Stop-Vm ($hv) {
    if ($KeepRunning) { Warn "-KeepRunning set; leaving VM powered on"; return }
    Log "powering off VM"
    try {
        switch ($hv) {
            'virtualbox' { & VBoxManage controlvm $VmName acpipowerbutton 2>$null; Start-Sleep 8; & VBoxManage controlvm $VmName poweroff 2>$null | Out-Null }
            'vmware'     { & vmrun stop $Vmx soft 2>$null | Out-Null }
            'hyperv'     { Stop-VM -Name $VmName -Force -ErrorAction SilentlyContinue | Out-Null }
        }
        Ok "VM powered off"
    } catch { Warn "best-effort power off failed: $_" }
}

function Get-GuestIp ($hv) {
    if ($GuestHost) { return $GuestHost }
    Log "resolving guest IP from hypervisor"
    switch ($hv) {
        'virtualbox' {
            $ip = (& VBoxManage guestproperty get $VmName '/VirtualBox/GuestInfo/Net/0/V4/IP') 2>$null
            if ($ip -match 'Value:\s*(\d+\.\d+\.\d+\.\d+)') { return $Matches[1] }
        }
        'vmware' {
            $ip = (& vmrun getGuestIPAddress $Vmx -wait) 2>$null
            if ($ip -match '(\d+\.\d+\.\d+\.\d+)') { return $Matches[1] }
        }
        'hyperv' {
            $ip = (Get-VMNetworkAdapter -VMName $VmName).IPAddresses |
                  Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' } | Select-Object -First 1
            if ($ip) { return $ip }
        }
    }
    Die "could not resolve guest IP; pass -GuestHost explicitly."
}

# ---------------------------------------------------------------------------
# Remote exec abstraction
# ---------------------------------------------------------------------------
$script:SshTarget = $null
$script:SshOpts   = @()
$script:VboxPwFile = $null

function Init-Exec ($hv, $execMode) {
    if (-not $GuestUser) { Die "guest user required: pass -GuestUser or set APTW_GUEST_USER." }
    if ($execMode -eq 'ssh') {
        Require-Cmd ssh
        $ip = Get-GuestIp $hv
        $script:SshTarget = "$GuestUser@$ip"
        $script:SshOpts = @('-o','StrictHostKeyChecking=accept-new','-o','ConnectTimeout=10')
        if ($GuestKey) { $script:SshOpts += @('-i', $GuestKey) }
        Ok "SSH target: $script:SshTarget"
    } else {
        if ($hv -eq 'hyperv') { Die "guest-control is not available for a Linux guest under Hyper-V; use -Exec ssh." }
        if (-not $GuestPassword) { Die "guest-control needs -GuestPassword (or APTW_GUEST_PASSWORD)." }
        if ($hv -eq 'virtualbox') {
            # Pass the guest password via a temp file, never on the command line.
            $script:VboxPwFile = Join-Path $env:TEMP ("aptw-vbpw-" + [guid]::NewGuid().ToString('N'))
            Set-Content -Path $script:VboxPwFile -Value $GuestPassword -NoNewline -Encoding ascii
        }
        Ok "guest-control mode ($hv)"
    }
}

# Run a bash command line in the guest; returns the process exit code.
function Invoke-Guest ($hv, $execMode, [string] $BashCmd) {
    if ($execMode -eq 'ssh') {
        & ssh @script:SshOpts $script:SshTarget "bash -lc `"$BashCmd`"" | Out-Host
        return $LASTEXITCODE
    }
    switch ($hv) {
        'virtualbox' {
            & VBoxManage guestcontrol $VmName run --username $GuestUser --passwordfile $script:VboxPwFile `
                --exe /bin/bash -- bash -lc "$BashCmd" | Out-Host
            return $LASTEXITCODE
        }
        'vmware' {
            & vmrun -gu $GuestUser -gp $GuestPassword runProgramInGuest $Vmx /bin/bash -lc "$BashCmd" | Out-Host
            return $LASTEXITCODE
        }
    }
    return 1
}

# Copy the local repo tree into the guest (local-source mode).
function Copy-RepoToGuest ($hv, $execMode) {
    $excludes = @('.venv','vm','.git','site','__pycache__','.pytest_cache')
    Log "delivering local repo to guest (excluding: $($excludes -join ', '))"
    if ($execMode -eq 'ssh') {
        Require-Cmd scp
        # Stage a clean copy first so we don't push .venv / vm image over the wire.
        $stage = Join-Path $env:TEMP ("aptw-stage-" + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $stage | Out-Null
        try {
            robocopy $LocalRepo $stage /E /NFL /NDL /NJH /NJS /NP `
                /XD ($excludes | ForEach-Object { Join-Path $LocalRepo $_ }) | Out-Null
            Invoke-Guest $hv $execMode "rm -rf $TargetDir && mkdir -p $TargetDir" | Out-Null
            & scp @script:SshOpts -r (Join-Path $stage '*') "$($script:SshTarget):$TargetDir/" | Out-Host
        } finally { Remove-Item -Recurse -Force $stage -ErrorAction SilentlyContinue }
    } elseif ($hv -eq 'virtualbox') {
        # SSH-free delivery: stage a clean tree, copy it in with VBoxManage,
        # then assemble it at the target path inside the guest.
        $stage = Join-Path $env:TEMP 'aptw-src'
        if (Test-Path $stage) { Remove-Item -Recurse -Force $stage }
        New-Item -ItemType Directory -Path $stage | Out-Null
        try {
            robocopy $LocalRepo $stage /E /NFL /NDL /NJH /NJS /NP `
                /XD ($excludes | ForEach-Object { Join-Path $LocalRepo $_ }) | Out-Null
            Invoke-Guest $hv $execMode "rm -rf /tmp/aptw-src" | Out-Null
            & VBoxManage guestcontrol $VmName copyto --username $GuestUser --passwordfile $script:VboxPwFile `
                --recursive --target-directory /tmp "$stage" | Out-Host
            $assemble = "rm -rf $TargetDir && mkdir -p $TargetDir && cp -a /tmp/aptw-src/. $TargetDir/ && rm -rf /tmp/aptw-src"
            if ((Invoke-Guest $hv $execMode $assemble) -ne 0) { Die "guest-side assemble of copied tree failed" }
        } finally { Remove-Item -Recurse -Force $stage -ErrorAction SilentlyContinue }
    } else {
        Die "local-source copy over guest-control is only implemented for VirtualBox; use -Exec ssh, or -Source git."
    }
    Ok "local repo delivered to $TargetDir"
}

function Deliver-Code ($hv, $execMode) {
    if ($Source -eq 'git') {
        Log "git clone/pull $RepoUrl -> $TargetDir (in guest)"
        $cmd = "if [ -d $TargetDir/.git ]; then git -C $TargetDir pull --ff-only; else git clone $RepoUrl $TargetDir; fi"
        if ((Invoke-Guest $hv $execMode $cmd) -ne 0) { Die "git delivery failed in guest" }
    } else {
        Copy-RepoToGuest $hv $execMode
    }
    Ok "code delivered"
}

# ---------------------------------------------------------------------------
# Wait for guest readiness
# ---------------------------------------------------------------------------
function Wait-Guest ($hv, $execMode) {
    Log "waiting for guest to become reachable (timeout ${BootTimeoutSec}s)"
    $deadline = (Get-Date).AddSeconds($BootTimeoutSec)
    while ((Get-Date) -lt $deadline) {
        try {
            if ((Invoke-Guest $hv $execMode "true") -eq 0) { Ok "guest is reachable"; return }
        } catch { }
        Start-Sleep 5
    }
    Die "guest did not become reachable within ${BootTimeoutSec}s"
}

# ===========================================================================
# Main
# ===========================================================================
$hv = Resolve-Hypervisor
$execMode = Resolve-Exec $hv
Log "hypervisor=$hv exec=$execMode source=$Source"

$gateExit = 1
try {
    Start-Vm $hv
    Init-Exec $hv $execMode
    Wait-Guest $hv $execMode
    Deliver-Code $hv $execMode

    Log "running prepare-vm.sh in guest"
    if ((Invoke-Guest $hv $execMode "cd $TargetDir && bash scripts/prepare-vm.sh") -ne 0) {
        Warn "prepare-vm.sh reported issues (continuing to gates for full picture)"
    }

    $fastFlag = if ($Fast) { ' --fast' } else { '' }
    Log "running run-gates.sh$fastFlag in guest"
    $gateExit = Invoke-Guest $hv $execMode "cd $TargetDir && source .venv/bin/activate && bash scripts/run-gates.sh$fastFlag"

    # Pull gate logs back to the host.
    $logDir = Join-Path $LocalRepo 'vm-test-logs'
    New-Item -ItemType Directory -Path $logDir -Force | Out-Null
    if ($execMode -eq 'ssh') {
        & scp @script:SshOpts "$($script:SshTarget):/tmp/aptw_*.log" "$logDir/" 2>$null
        Log "gate logs copied to $logDir (if any)"
    } elseif ($hv -eq 'virtualbox') {
        # VBoxManage copyfrom needs explicit filenames; copy the known gate logs.
        foreach ($name in @('aptw_pytest.log','aptw_ruff.log','aptw_mypy.log','aptw_eval.log','aptw_mkdocs.log','aptw_cleanroom.log')) {
            & VBoxManage guestcontrol $VmName copyfrom --username $GuestUser --passwordfile $script:VboxPwFile `
                --target-directory $logDir "/tmp/$name" 2>$null
        }
        Log "gate logs copied to $logDir (if any)"
    }
}
finally {
    Stop-Vm $hv
    if ($script:VboxPwFile -and (Test-Path $script:VboxPwFile)) {
        Remove-Item -Force $script:VboxPwFile -ErrorAction SilentlyContinue
    }
}

Write-Host ''
if ($gateExit -eq 0) {
    Ok "AUTONOMOUS VM TEST PASSED -- all gates green inside the VM"
} else {
    Warn "AUTONOMOUS VM TEST FAILED -- run-gates.sh exit code $gateExit (see output / vm-test-logs)"
}
exit $gateExit

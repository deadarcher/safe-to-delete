<#
.SYNOPSIS
    Report what is eating a Windows system drive, and how confident you can be about reclaiming
    each part of it. REPORTS BY DEFAULT - it deletes only when you pass -Apply.

.DESCRIPTION
    Space analysers (WizTree, TreeSize) tell you WHERE the bytes are, and they are excellent at it.
    Cleanup scripts DELETE things, and there are a dozen good ones on GitHub. Neither answers the
    question in between, which is the one that actually stops people:

        "Which of this is safe to remove, and what does removing it cost me?"

    Worked example from the machine this was written on. The Windows Installer cache is 6.5 GB. Of
    that, 403 MB is genuinely orphaned; deleting the other 6 GB breaks repair and uninstall for 143
    installed products, and the user finds out weeks later with "the feature you are trying to use
    is on a network resource that is unavailable". A size report cannot tell those apart. A cleanup
    script that empties the folder is actively dangerous. Only a tool that checks each file against
    the installer database can say which 403 MB is which.

    So every finding carries a CONFIDENCE and a stated COST:

      safe     - regenerated on demand, or already dead. Removing it loses nothing.
      caution  - reclaimable, but you give something up, and the something is named.
      leave    - in use. Listed so you know why the space is not available to you.

    WHY A SIGNED SCRIPT AND NOT AN EXE. The best-known tool for the installer-cache half of this is
    an unsigned binary from around 2012. You are being asked to let an unsigned executable delete
    files from C:\Windows\Installer on faith. A signed script is strictly more auditable: you can
    read exactly what it is about to do before you run it. Nothing here needs compiled code.

    WHY NOT JUST cleanmgr /sagerun. The built-in needs a registry preset configured per machine
    before it will run unattended, emits nothing you can parse, and its target list is not
    inspectable - you cannot read it and know what it is about to delete. This is a readable script
    that names every target, its size, and what removing it costs you, before anything is removed.

    INVARIANTS. These are boundaries, not preferences, and they hold whatever switches you pass:

      * USER DATA IS NEVER TOUCHED. Not Downloads, Documents, Desktop, Pictures, or anything
        OneDrive-backed. Deleting a user's Downloads folder is the single most hated behaviour in
        the consumer-cleanup category and this tool does not have that code path at all. The only
        user-profile paths it will ever remove from are AppData\Local\Temp and application caches
        that the application rebuilds on next launch.
      * NOTHING IS DELETED WITHOUT -Apply. The default run reports.
      * IT REFUSES TO RUN DURING AN INSTALL. See -IgnoreActiveInstalls; a cleanup that races a
        patch cycle is how you manufacture a support ticket.
      * NOTHING IS UPLOADED. The JSON is written to your disk and read in your browser.
      * IT NEVER REBOOTS ANYTHING. If the component store needs a restart to finish, it says so and
        exits 3010 for your RMM to act on.

.PARAMETER OutFile
    Where to write the JSON snapshot. Defaults to disk-reclaim.json on your Desktop.

.PARAMETER Gui
    Show a results window instead of console output. Still read-only.

.PARAMETER Quick
    Skip the slow checks (per-profile sizing, component-store analysis). Seconds instead of minutes.

.PARAMETER StaleProfileDays
    A local profile unused for this many days is reported. Default 90.

.PARAMETER Category
    Only run these categories: temp, updates, caches, installer, dumps, images, profiles, system.
    Default is all of them.

.EXAMPLE
    powershell -ExecutionPolicy RemoteSigned -File safe-to-delete.ps1
.EXAMPLE
    powershell -ExecutionPolicy RemoteSigned -File safe-to-delete.ps1 -Gui
.EXAMPLE
    powershell -ExecutionPolicy RemoteSigned -File safe-to-delete.ps1 -Quick -Category temp,updates
#>
# SupportsShouldProcess gives -WhatIf and -Confirm for free, and ConfirmImpact High means -Apply
# prompts unless the caller passes -Confirm:$false. Deleting from someone else's system drive should
# have to be asked for twice.
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    # Empty = "work it out below". NOT "$env:USERPROFILE\Desktop": when Known Folder Move redirects
    # the Desktop into OneDrive, that literal path still EXISTS and is a stale empty folder nobody
    # opens - so the report and the removal log land somewhere the operator will never find them.
    # Resolved through the shell instead, which follows the redirection. See Resolve-OutputDir.
    [string]   $OutFile = '',
    [switch]   $Gui,
    [switch]   $Quick,
    [int]      $StaleProfileDays = 90,
    # NO ValidateSet, on purpose - it is enforced by hand below. powershell.exe -File hands array
    # arguments to a script as ONE string, so "-Category temp,updates" arrives as the single value
    # "temp,updates" and ValidateSet rejects it. The .EXAMPLE above used exactly that form, and it
    # had never worked. Checked by hand after splitting instead, so the documented call is valid.
    [string[]] $Category = @('temp','updates','caches','installer','dumps','images','profiles','system'),

    # ---- the delete side. Everything above this line is read-only and always has been. ----

    # Actually remove what was found. Without it this script does exactly what it always did.
    [switch]   $Apply,
    # Widen -Apply from the safe list to the caution list. Each caution item costs you something
    # real and the report names it, so this is deliberately a second, separate decision.
    [switch]   $IncludeCaution,
    # Where to write the record of what was removed. A plain-text .log, one line per FILE with its
    # full path, APPENDED so each run adds to the history. See the Write-RemovalLog block below for
    # why this is not JSON.
    [string]   $ApplyLog = '',
    # Skip writing that record. ON by default because a destructive run you cannot account for
    # afterwards is the one you regret, but there are real reasons to turn it off: a kiosk or
    # shared box where a file on the Desktop is clutter, a read-only profile, or an RMM that
    # already captures the transcript. Deliberately a switch to SUPPRESS rather than one to
    # enable - the safe behaviour should be what you get by doing nothing.
    [switch]   $NoRemovalLog,

    # Only do anything when the system drive is actually under pressure. Running a 30-minute
    # component-store pass across 400 healthy machines is wasted time and a support call. 0 = always
    # run, which is the right default for a human at a keyboard; an RMM should set it.
    [int]      $OnlyIfFreePercentBelow = 0,

    # How old a temp file must be before it counts as reclaimable. 1 day already covers the case
    # that matters - an installer writing to temp RIGHT NOW - because installers finish in minutes,
    # not days. Raised to 7 by cautious operators; exposed rather than hard-coded so that is their
    # call and not a guess baked into the script.
    [int]      $TempAgeDays = 1,

    # Proceed even when an install is in flight. Exists so an operator who KNOWS the msiexec on the
    # box is their own long-running deploy can override, and for lab use. Not the default, because
    # the failure it prevents is a broken install with a baffling error message.
    [switch]   $IgnoreActiveInstalls,

    # Cap on the component-store cleanup, which is the one action here that can hang. Exceeding it
    # is reported and skipped, never left pending forever.
    [int]      $ComponentCleanupTimeoutMins = 30,
    # Answer the confirmation prompt in advance. THIS EXISTS BECAUSE -Confirm:$false CANNOT BE
    # PASSED THROUGH -File: powershell.exe -File hands the rest of the command line to the script as
    # plain strings, so "-Confirm:$false" arrives as the literal text '$false' and dies with
    # "Cannot convert 'System.String' to the type 'SwitchParameter'". Every unattended caller - RMM,
    # Task Scheduler, SCCM - invokes with -File, so without this switch -Apply would sit on a
    # prompt no one can answer until the job times out. Found by running it that way (2026-09-11).
    [switch]   $Force
)

# Split the comma-joined form back apart, then validate. Accepts both -Category temp,updates (via
# -File) and -Category temp,updates as a real array (when dot-sourced or called from PowerShell).
$Category = @($Category | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
$validCategories = @('temp','updates','caches','installer','dumps','images','profiles','system')
$badCategories = @($Category | Where-Object { $validCategories -notcontains $_ })
if ($badCategories.Count -gt 0) {
    throw "Unknown -Category value(s): $($badCategories -join ', '). Valid values are: $($validCategories -join ', ')"
}

$ErrorActionPreference = 'SilentlyContinue'

# -- Where the two output files go ---------------------------------------------------------------
# The Desktop is the right default - it is where a tech looks for the thing they just ran - but
# "$env:USERPROFILE\Desktop" is the wrong way to find it. With OneDrive Known Folder Move the real
# Desktop is $env:OneDrive\Desktop, while C:\Users\<name>\Desktop survives as a stale empty folder.
# Writing there means the report and the removal log exist, are correct, and are invisible.
#
# GetFolderPath('DesktopDirectory') reads the shell's own Desktop location, so it follows the
# redirection. Two cases it does NOT cover, both real for this tool:
#   - running as SYSTEM from an RMM: there is a profile, but nobody will ever open its Desktop
#   - a redirected Desktop that is offline or otherwise not currently a directory
# Both fall back to the temp directory, which is always writable and which the console output and
# the GUI footer name explicitly, so the file is never merely lost.
function Resolve-OutputDir {
    $d = ''
    try { $d = [Environment]::GetFolderPath([Environment+SpecialFolder]::DesktopDirectory) } catch { }
    if ([string]::IsNullOrWhiteSpace($d) -or -not (Test-Path -LiteralPath $d -PathType Container)) {
        $d = Join-Path $env:USERPROFILE 'Desktop'
    }
    if (-not (Test-Path -LiteralPath $d -PathType Container)) { $d = [IO.Path]::GetTempPath() }
    return $d.TrimEnd('\')
}
if ([string]::IsNullOrWhiteSpace($OutFile))  { $OutFile  = Join-Path (Resolve-OutputDir) 'disk-reclaim.json' }
if ([string]::IsNullOrWhiteSpace($ApplyLog)) { $ApplyLog = Join-Path (Resolve-OutputDir) 'disk-reclaim-removed.log' }

# -Force means "I have already decided", so stand down the ConfirmImpact High prompt. Setting the
# preference is the only way to do this from inside the script; the caller cannot reach $ConfirmPreference.
if ($Force) { $ConfirmPreference = 'None' }
$sw = [Diagnostics.Stopwatch]::StartNew()

# -- Exit codes, so an RMM can act on this without scraping the text -----------------------------
#   0    nothing to do, or done cleanly
#   3010 removal succeeded and something needs a reboot to finish (component store)
#   2    refused to run - an install is in flight, or the drive is not under the threshold
#   1    a real failure
$script:exitCode = 0
$script:needsReboot = $false

# -- Refuse to run during an install -------------------------------------------------------------
#
# Deleting out of temp while msiexec is mid-transaction destroys the installer's own working
# directory, and the deploy fails with an error that names none of this. The age threshold on temp
# already covers most of it; this is the belt to that suspenders, and it also catches the component
# store being busy, which is where the expensive actions would collide.
function Get-ActiveInstallBlockers {
    $blockers = @()
    foreach ($p in @('TrustedInstaller', 'TiWorker', 'setup', 'setuphost', 'wusa')) {
        $procs = @(Get-Process -Name $p -ErrorAction SilentlyContinue)
        if ($procs.Count -gt 0) { $blockers += "$p x$($procs.Count)" }
    }

    # msiexec needs its COMMAND LINE, not a count. The resident service instance runs as
    # "msiexec.exe /V" and lingers on an idle box, so counting is ambiguous in both directions: an
    # earlier version required MORE THAN ONE instance to allow for it, and on a machine with no
    # resident instance at all - which is most of them - a single real installer then sailed
    # straight past the guard. Measured 2026-09-18: zero resident instances on the test box, one
    # genuine msiexec running, guard silent. Filter the service out by its switch instead.
    try {
        $msi = @(Get-CimInstance Win32_Process -Filter "Name='msiexec.exe'" -ErrorAction Stop |
                 Where-Object { $_.CommandLine -notmatch '(?i)\s/V\b' })
        if ($msi.Count -gt 0) { $blockers += "msiexec x$($msi.Count)" }
    } catch {
        # No CIM (locked down, WMI broken): fall back to presence. Over-refusing is the safe
        # direction for a guard whose job is to prevent a broken install.
        $any = @(Get-Process -Name msiexec -ErrorAction SilentlyContinue)
        if ($any.Count -gt 0) { $blockers += "msiexec x$($any.Count)" }
    }
    # RFF's own agent mid-deploy. Absent on a machine that does not run RFF, which is fine.
    if (Get-Process -Name 'RFF' -ErrorAction SilentlyContinue) { $blockers += 'RFF deploy' }
    $blockers
}

if ($Apply -and -not $IgnoreActiveInstalls) {
    $blockers = Get-ActiveInstallBlockers
    if ($blockers.Count -gt 0) {
        Write-Host ''
        Write-Host "  REFUSING TO REMOVE - an install looks active: $($blockers -join ', ')" -ForegroundColor Red
        Write-Host '  Cleaning temp while an installer is using it breaks the install, and the error it' -ForegroundColor DarkGray
        Write-Host '  produces will not mention this script. Re-run when it finishes, or pass' -ForegroundColor DarkGray
        Write-Host '  -IgnoreActiveInstalls if you know that process is yours.' -ForegroundColor DarkGray
        Write-Host ''
        exit 2
    }
}

# -- Only act when the drive is actually under pressure ------------------------------------------
if ($OnlyIfFreePercentBelow -gt 0) {
    $vol = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$env:SystemDrive'"
    $freePct = if ($vol.Size -gt 0) { [math]::Round(100 * $vol.FreeSpace / $vol.Size, 1) } else { 0 }
    if ($freePct -ge $OnlyIfFreePercentBelow) {
        Write-Host ''
        Write-Host ("  Nothing to do: {0} is {1}% free, threshold is below {2}%." -f $env:SystemDrive, $freePct, $OnlyIfFreePercentBelow)
        Write-Host ''
        exit 0
    }
}

# Progress, because a 95-second silence reads as a hang.
#
# -Gui is the worst case: the console prints nothing at all and no window exists yet, so the only
# feedback is the cursor. Someone who runs `.\disk-reclaim-report.ps1 -Gui` and waits a minute and a
# half in silence reasonably concludes it did nothing. Write-Progress covers the console; the extra
# line for -Gui says a window is coming, so the wait is expected rather than suspicious.
$script:phaseNo = 0
$script:phaseTotal = 8
function Set-Phase {
    param([string] $Label)
    $script:phaseNo++
    $pct = [int](100 * $script:phaseNo / $script:phaseTotal)
    Write-Progress -Activity 'Disk reclaim scan' -Status "$Label ($script:phaseNo of $script:phaseTotal)" -PercentComplete $pct
    if ($Gui) { Write-Host ("  [{0}/{1}] {2}" -f $script:phaseNo, $script:phaseTotal, $Label) -ForegroundColor DarkGray }
}
if ($Gui) {
    Write-Host ''
    Write-Host '  Scanning this machine - the results window opens when it finishes.' -ForegroundColor Cyan
    Write-Host '  A full scan is usually 30-90 seconds. Add -Quick to skip the slow folder walks.' -ForegroundColor DarkGray
    Write-Host ''
}
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

$findings     = @()
$notes        = @()
$orphanFiles  = @()
function Want { param([string] $C) return ($Category -contains $C) }

function Add-Finding {
    # -Where is the path. A finding that says "2.4 GB of per-user temp" without saying WHERE is a
    # number you have to go and re-derive before you can act on it, and re-deriving it by hand is
    # exactly where somebody deletes the wrong folder. Wherever the path is already in a variable
    # the caller passes that same variable, so the path and the size cannot drift apart.
    param([string] $Id, [string] $Name, [double] $Mb, [string] $Confidence,
          [string] $Cat, [string] $What, [string] $Cost, [string] $How = '', [string] $Where = '')
    $script:findings += [ordered]@{
        id = $Id; name = $Name; sizeMB = [math]::Round($Mb, 1); confidence = $Confidence
        category = $Cat; location = $Where; what = $What; cost = $Cost; how = $How
    }
}

# ============================================================================================
#  THE DELETE SIDE
#
#  Everything above stays read-only. This runs only when -Apply is passed, and it is built on one
#  rule: a finding can only be removed by an action written FOR IT, by id. There is deliberately no
#  generic "delete whatever is in .location", because the locations are prose meant for a human -
#  "C:\Users\*\AppData\Local\Temp", "Inside the C: volume - no folder to browse". Handing those to
#  Remove-Item is how a cleanup tool destroys a machine.
#
#  So an id with no action here is simply not cleanable, and says so. Two are refused on purpose,
#  documented in Invoke-ReclaimAction.
# ============================================================================================

$script:freedBytes = 0
$script:removedCount = 0
$script:skippedCount = 0
# NOT $script:applyLog. PowerShell variable names are CASE-INSENSITIVE, so $script:applyLog and
# the $ApplyLog parameter are the same variable - assigning @() to it blanked the log path, and
# the script then reported 'Removal log : ' with nothing after it and silently wrote no record.
$script:applyItems = @()
$script:externalIds = @()

# ---- the removal log ------------------------------------------------------------------------
# A .log, not a .json, and APPENDED rather than overwritten. This file exists for one job: six
# weeks from now someone asks "what deleted my file", and a person - not a program - has to answer
# it. That means Notepad, findstr and Ctrl-F, so it is fixed-width plain text with the full path on
# every line, and every run adds to the history instead of erasing the last one.
#
# It is written STREAMING, as each path goes, not assembled at the end. A cleanup that is killed
# half way through is exactly when the record matters most, and a log that only exists if the
# script reaches its last line is not a record of anything.
#
# The machine-readable copy still exists: the JSON snapshot carries the same run as structured
# per-category totals for an RMM to parse. Two files because they have two readers.
$script:logWriter = $null

function Write-RemovalLog {
    param([string] $Line)
    if ($null -eq $script:logWriter) { return }
    try { $script:logWriter.WriteLine($Line) } catch { }
}

# ---- keeping the window alive while it works ---------------------------------------------------
# WinForms runs everything on one thread, so a delete loop that never yields makes Windows grey the
# title bar out and append "(Not Responding)". On a tool that is midway through deleting files, that
# is the worst possible moment to look hung: the operator's next move is to end the task, and now
# nobody knows what was removed and what was not.
#
# So the engine calls back every few files and the GUI pumps the message queue there. Null in
# console mode, which keeps Remove-OnePath free of any dependency on the window existing.
$script:onProgress = $null
$script:progressTick = 0

function Signal-Progress {
    param([string] $Path)
    if ($null -eq $script:onProgress) { return }
    # Pumping on EVERY file would spend more time in the message loop than in the deletes on a
    # folder of tiny files. Every 25 is often enough that Windows never marks the window hung.
    $script:progressTick++
    if ($script:progressTick % 25 -ne 0) { return }
    try { & $script:onProgress $Path } catch { }
}

function Open-RemovalLog {
    # Returns $true if the log is open. A failure here is reported and then ignored: losing the
    # audit trail is bad, refusing to clean a full disk because the Desktop is read-only is worse.
    param([string] $Path, [string] $Source)
    try {
        $dir = Split-Path -Parent $Path
        if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        # append: $true. The history IS the point.
        $script:logWriter = New-Object System.IO.StreamWriter($Path, $true, [System.Text.UTF8Encoding]::new($false))
        $script:logWriter.AutoFlush = $true
    } catch {
        Write-Host ("  Could not open the removal log ({0}): {1}" -f $Path, $_.Exception.Message) -ForegroundColor DarkYellow
        $script:logWriter = $null
        return $false
    }
    Write-RemovalLog ''
    Write-RemovalLog ('=' * 100)
    Write-RemovalLog ("{0}  {1}  disk-reclaim {2}" -f (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'), $env:COMPUTERNAME, $Source)
    Write-RemovalLog ("    run by {0}\{1}   elevated={2}   caution items included={3}" -f $env:USERDOMAIN, $env:USERNAME, $(if ($isAdmin) { 'yes' } else { 'NO' }), $(if ($IncludeCaution) { 'yes' } else { 'no' }))
    Write-RemovalLog ('=' * 100)
    return $true
}

function Close-RemovalLog {
    if ($null -eq $script:logWriter) { return }
    try { $script:logWriter.Flush(); $script:logWriter.Dispose() } catch { }
    $script:logWriter = $null
}

function Remove-OnePath {
    # Deletes ONE file or directory and returns the bytes it accounted for. Every failure is
    # counted and swallowed: on a live system some of these files are always open, and a locked
    # temp file is a normal Tuesday, not a reason to abandon the rest of the run.
    param([string] $Path)
    if (-not (Test-Path -LiteralPath $Path)) { return 0 }
    $bytes = 0
    try {
        $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        if ($item.PSIsContainer) {
            foreach ($f in (Get-ChildItem -LiteralPath $Path -Recurse -File -Force -ErrorAction SilentlyContinue)) {
                $bytes += $f.Length
            }
        } else {
            $bytes = $item.Length
        }
        Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop
        $script:freedBytes += $bytes
        $script:removedCount++
        Write-RemovalLog ("{0}  DELETED  {1,12:N0} KB  {2}" -f (Get-Date).ToString('HH:mm:ss'), ($bytes / 1KB), $Path)
        Signal-Progress $Path
        return $bytes
    } catch {
        $script:skippedCount++
        # The locked ones are the interesting lines. "Why is C:\Windows\Temp still 400 MB" is
        # answered here and nowhere else, so the reason goes in rather than just the path.
        # The 5 trailing spaces line the path up under the DELETED lines' paths - ' KB' plus the
        # two-space gap. Columns that drift are columns nobody scans down.
        Write-RemovalLog ("{0}  LOCKED   {1,12}     {2}  <- {3}" -f (Get-Date).ToString('HH:mm:ss'), '-', $Path, $_.Exception.Message)
        return 0
    }
}

function Clear-FolderContents {
    # Empties a folder but KEEPS the folder. Windows recreates most of these lazily, but some
    # (Temp, Logs\CBS) are expected to exist by whatever writes to them, and deleting the container
    # turns a cleanup into an outage on the next write.
    #
    # THE AGE TEST IS PER FILE, because that is what the scan measures. The first version tested the
    # timestamp of each top-level CHILD, so a freshly created subfolder full of week-old junk was
    # skipped whole: the report counted 160 MB in C:\Windows\Temp and -Apply freed 0.0 MB of it.
    # An estimate and a result produced by different rules make the "actual gain" number worthless,
    # which is the one number this thing promises to get right.
    param([string] $Path, [int] $OlderThanDays = 0, [string[]] $Ext)
    if (-not (Test-Path -LiteralPath $Path)) { return }
    $cut = (Get-Date).AddDays(-$OlderThanDays)

    foreach ($f in (Get-ChildItem -LiteralPath $Path -Recurse -File -Force -ErrorAction SilentlyContinue)) {
        if ($OlderThanDays -gt 0 -and $f.LastWriteTime -ge $cut) { continue }
        if ($Ext -and ($Ext -notcontains $f.Extension)) { continue }
        [void](Remove-OnePath $f.FullName)
    }

    # Tidy up the directories the files came out of, deepest first, and only if they ended up empty.
    # Skipped entirely in -Ext mode: there we are picking specific files out of a folder that has
    # every right to still be there (C:\Windows\inf is the worked example).
    if (-not $Ext) {
        $dirs = Get-ChildItem -LiteralPath $Path -Recurse -Directory -Force -ErrorAction SilentlyContinue |
                Sort-Object { $_.FullName.Length } -Descending
        foreach ($d in $dirs) {
            if (-not (Get-ChildItem -LiteralPath $d.FullName -Force -ErrorAction SilentlyContinue)) {
                Remove-Item -LiteralPath $d.FullName -Force -ErrorAction SilentlyContinue
            }
        }
    }
}

function Invoke-ReclaimAction {
    # Returns one of three STRINGS: 'counted' (we deleted the files and counted the bytes),
    # 'external' (Windows did the deleting - DISM, the shell, powercfg - so there are no bytes to
    # attribute) or 'none' (no action exists for this id; the operator is told, never silently
    # skipped).
    #
    # STRINGS, NOT BOOLEANS, and that is the whole reason this contract changed. The first version
    # returned $true/'external', and `$handled -eq 'external'` coerces the RIGHT operand to the
    # LEFT operand's type - so $true -eq 'external' is True, because a non-empty string is a
    # truthy boolean. Every counted action reported itself as external and the summary read
    # 'REMOVED: 0 MB' after deleting 280 MB.
    param([string] $Id)
    switch ($Id) {

        # ---- safe ----
        'win-temp'   { Clear-FolderContents "$env:SystemRoot\Temp" -OlderThanDays $TempAgeDays; return 'counted' }
        'user-temp'  {
            foreach ($u in (Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue)) {
                Clear-FolderContents (Join-Path $u.FullName 'AppData\Local\Temp') -OlderThanDays $TempAgeDays
            }
            return 'counted'
        }
        'teams-cache' {
            foreach ($u in (Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue)) {
                Clear-FolderContents (Join-Path $u.FullName 'AppData\Roaming\Microsoft\Teams')
                Clear-FolderContents (Join-Path $u.FullName 'AppData\Local\Packages\MSTeams_8wekyb3d8bbwe\LocalCache')
            }
            return 'counted'
        }
        'browser-cache' {
            foreach ($u in (Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue)) {
                Clear-FolderContents (Join-Path $u.FullName 'AppData\Local\Google\Chrome\User Data\Default\Cache')
                Clear-FolderContents (Join-Path $u.FullName 'AppData\Local\Microsoft\Edge\User Data\Default\Cache')
                # Firefox: only the cache2 tree, not the whole Profiles folder. Local\Profiles also
                # holds startupCache and safebrowsing, which are cheap to lose - but scoping it to
                # cache2 means this cannot drift into anything that matters if Mozilla moves things.
                $ffRoot = Join-Path $u.FullName 'AppData\Local\Mozilla\Firefox\Profiles'
                foreach ($prof in (Get-ChildItem -LiteralPath $ffRoot -Directory -ErrorAction SilentlyContinue)) {
                    Clear-FolderContents (Join-Path $prof.FullName 'cache2')
                }
            }
            return 'counted'
        }
        'wu-cache' {
            # Stop the service first or half of it is locked, then ALWAYS start it again. Leaving
            # Windows Update stopped because a cleanup threw would be a far worse bug than the
            # space it reclaimed.
            $was = (Get-Service wuauserv -ErrorAction SilentlyContinue).Status
            try {
                if ($was -eq 'Running') { Stop-Service wuauserv -Force -ErrorAction SilentlyContinue }
                Clear-FolderContents "$env:SystemRoot\SoftwareDistribution\Download"
            } finally {
                if ($was -eq 'Running') { Start-Service wuauserv -ErrorAction SilentlyContinue }
            }
            return 'counted'
        }
        'delivery-opt' {
            Clear-FolderContents "$env:SystemRoot\SoftwareDistribution\DeliveryOptimization"
            Clear-FolderContents "$env:ProgramData\Microsoft\Windows\DeliveryOptimization"
            return 'counted'
        }
        'cbs-logs'   { Clear-FolderContents "$env:SystemRoot\Logs\CBS"; return 'counted' }
        'panther'    {
            Clear-FolderContents "$env:SystemRoot\Panther"
            # LOGS ONLY. The .inf and .PNF files beside them are the driver store; deleting those
            # costs you driver installation permanently. This is the whole reason the finding was
            # rescoped - see the panther block above.
            Clear-FolderContents "$env:SystemRoot\inf" -Ext @('.log', '.txt')
            return 'counted'
        }
        'installer-orphans' {
            # Exactly the files the scan proved orphaned. Never a wildcard over C:\Windows\Installer.
            foreach ($f in $script:orphanFiles) { [void](Remove-OnePath $f) }
            return 'counted'
        }
        'memory-dmp' { [void](Remove-OnePath "$env:SystemRoot\MEMORY.DMP"); return 'counted' }
        'minidumps'  { Clear-FolderContents "$env:SystemRoot\Minidump"; return 'counted' }
        'wer'        {
            Clear-FolderContents "$env:ProgramData\Microsoft\Windows\WER\ReportQueue"
            Clear-FolderContents "$env:ProgramData\Microsoft\Windows\WER\ReportArchive"
            return 'counted'
        }

        # ---- caution: only with -IncludeCaution ----
        'recycle' {
            $before = $script:freedBytes
            try {
                Clear-RecycleBin -DriveLetter C -Force -ErrorAction Stop
                $script:removedCount++
            } catch { $script:skippedCount++ }
            # 'external': the shell emptied it, so we never saw the files and cannot count bytes.
            return 'external'
        }
        'winsxs' {
            # DISM, never Remove-Item. The component store is hard-linked into the live system and
            # deleting from it by hand corrupts servicing in a way that is not recoverable without
            # a repair install. This is the supported path and it is the ONLY one used here.
            # TIME-BOUNDED. This is the one action here that can hang, and an unbounded DISM leaves
            # an RMM job pending forever with nothing to report. Run it as a child process, wait
            # $ComponentCleanupTimeoutMins, then kill it and say so. A killed StartComponentCleanup
            # is safe to abandon - servicing rolls its own transaction back on next boot; that is
            # why the supported path is the only one used here.
            try {
                $dism = Start-Process -FilePath 'dism.exe' `
                    -ArgumentList '/Online /Cleanup-Image /StartComponentCleanup /Quiet' `
                    -PassThru -WindowStyle Hidden
                if ($dism.WaitForExit($ComponentCleanupTimeoutMins * 60 * 1000)) {
                    # 3010 from DISM means it finished and wants a restart to complete. Carry that
                    # up rather than swallowing it - the caller decides about reboots, not us.
                    if ($dism.ExitCode -eq 3010) { $script:needsReboot = $true }
                    if ($dism.ExitCode -eq 0 -or $dism.ExitCode -eq 3010) { $script:removedCount++ }
                    else { $script:skippedCount++ }
                } else {
                    try { $dism.Kill() } catch { }
                    $script:skippedCount++
                    $script:componentCleanupTimedOut = $true
                }
            } catch { $script:skippedCount++ }
            # 'external': DISM does the deleting inside the servicing stack. Measured at 5 GB on
            # a test VM, none of which this script could attribute - it shows in the volume delta.
            return 'external'
        }
        'windows-old' {
            # Owned by TrustedInstaller, so ownership has to move before anything can be removed.
            try {
                $null = & takeown.exe /F 'C:\Windows.old' /R /A /D Y 2>$null
                $null = & icacls.exe 'C:\Windows.old' /grant 'Administrators:F' /T /C /Q 2>$null
            } catch { }
            [void](Remove-OnePath 'C:\Windows.old')
            return 'counted'
        }
        'upgrade-staging' {
            [void](Remove-OnePath 'C:\$GetCurrent')
            [void](Remove-OnePath 'C:\$SysReset')
            return 'counted'
        }
        'hiberfil' {
            # This one is a CONFIGURATION CHANGE, not a delete: it turns hibernation off, which also
            # turns off fast startup. Reversible with powercfg /h on, and named as such in the log.
            try { $null = & powercfg.exe /hibernate off; $script:removedCount++ } catch { $script:skippedCount++ }
            return 'external'
        }

        # ---- refused on purpose, even with -IncludeCaution ----
        #
        # shadow-copies : deleting these destroys System Restore points and any VSS-based backup
        #                 history on the volume. That is a data-loss decision belonging to whoever
        #                 owns the machine's backup policy, not to a disk cleanup run.
        # stale-profiles: a profile is somebody's documents and desktop. "Unused for 90 days" is a
        #                 person on parental leave as often as it is a leaver. Reported, never
        #                 automated.
        default { return 'none' }
    }
}

# Sized with a single enumeration and no recursion into reparse points. The first version recursed
# everything and took 245 seconds; most of that was walking hard-linked and junctioned trees over
# and over, which also double-counts.
function FolderMB {
    # -Ext scopes the measurement to specific extensions. It exists because of C:\Windows\inf: that
    # folder is the DRIVER STORE, not a log folder, and measuring all of it counted 823 .inf and 711
    # .PNF files as reclaimable setup logs. See the panther finding for what that nearly cost.
    param([string] $Path, [int] $OlderThanDays = 0, [string[]] $Ext)
    if (-not (Test-Path -LiteralPath $Path)) { return 0 }
    $cut = (Get-Date).AddDays(-$OlderThanDays); $sum = 0

    # PS 5.1 COMPATIBLE ON PURPOSE. The first version used [System.IO.EnumerationOptions], which is
    # .NET Core only - on Windows PowerShell 5.1 (the default on every Windows box) it throws, the
    # catch swallowed it, and every folder measured 0. The tool cheerfully reported "nothing to
    # clean" on machines with gigabytes of temp files. It did not error; it lied quietly, which is
    # worse.
    #
    # Get-ChildItem -Recurse follows junctions and reparse points, which double-counts and is most
    # of why the first pass took 245 seconds, so the walk is done by hand with an explicit stack and
    # reparse points skipped.
    $stack = New-Object System.Collections.Stack
    $stack.Push($Path)
    while ($stack.Count -gt 0) {
        $dir = $stack.Pop()
        try { $di = New-Object System.IO.DirectoryInfo $dir } catch { continue }
        try {
            foreach ($f in $di.GetFiles()) {
                if ($OlderThanDays -gt 0 -and $f.LastWriteTime -ge $cut) { continue }
                if ($Ext -and $Ext -notcontains $f.Extension) { continue }
                $sum += $f.Length
            }
        } catch { }
        try {
            foreach ($sd in $di.GetDirectories()) {
                # Skip links, or WinSxS and profile trees get walked many times over.
                if ($sd.Attributes -band [System.IO.FileAttributes]::ReparsePoint) { continue }
                $stack.Push($sd.FullName)
            }
        } catch { }
    }
    return $sum / 1MB
}
function FileMB { param([string] $P) if (Test-Path -LiteralPath $P) { (Get-Item -LiteralPath $P -Force).Length / 1MB } else { 0 } }

# ---------------- temp ----------------
if (Want 'temp') {
    Set-Phase 'Temp folders'
    # Age-gated at 1 day: an installer running RIGHT NOW is writing to temp, and calling its working
    # files reclaimable is how a cleanup tool causes the next ticket.
    $winTemp = "$env:SystemRoot\Temp"
    Add-Finding 'win-temp' 'Windows temp folder' (FolderMB $winTemp $TempAgeDays) 'safe' 'temp' `
        'Files older than a day.' 'None - rewritten on demand.' '' -Where $winTemp

    $u = 0; foreach ($p in (Get-ChildItem 'C:\Users' -Directory)) { $u += FolderMB (Join-Path $p.FullName 'AppData\Local\Temp') $TempAgeDays }
    Add-Finding 'user-temp' 'Per-user temp folders' $u 'safe' 'temp' `
        'Every local profile, older than a day.' 'None.' '' `
        -Where 'C:\Users\*\AppData\Local\Temp'

    Add-Finding 'recycle' 'Recycle Bin' (FolderMB 'C:\$Recycle.Bin') 'caution' 'temp' `
        'Deleted files still recoverable by their owner.' `
        'Whatever is in there is gone for good. Check with the user before emptying someone else''s.' `
        'Storage Sense can empty it automatically after 30 or 60 days.' -Where 'C:\$Recycle.Bin'

    # Prefetch is on the list because people DELETE it expecting a win, and it is a mistake.
    $prefetch = "$env:SystemRoot\Prefetch"
    Add-Finding 'prefetch' 'Prefetch' (FolderMB $prefetch) 'leave' 'temp' `
        'Boot and application launch optimisation data.' `
        'Almost nothing to reclaim, and clearing it makes boot and first launches slower until Windows rebuilds it. You''ll see this one recommended a lot. Skip it.' `
        '' -Where $prefetch
}

# ---------------- updates ----------------
if (Want 'updates') {
    Set-Phase 'Windows Update cache'
    $wuDl = "$env:SystemRoot\SoftwareDistribution\Download"
    Add-Finding 'wu-cache' 'Windows Update download cache' (FolderMB $wuDl) 'safe' 'updates' `
        'Update payloads already installed or superseded.' 'None - Windows re-downloads what it needs.' `
        'Stop wuauserv first if you clear it by hand.' -Where $wuDl

    # Delivery Optimization is the one nobody looks at. Two locations, both real.
    $doPaths = @("$env:SystemRoot\SoftwareDistribution\DeliveryOptimization",
                 "$env:ProgramData\Microsoft\Windows\DeliveryOptimization")
    $do = 0; foreach ($d in $doPaths) { $do += FolderMB $d }
    Add-Finding 'delivery-opt' 'Delivery Optimization cache' $do 'safe' 'updates' `
        'Peer-to-peer update chunks this machine cached to share with others on the network.' `
        'None. Windows refills it as needed; on a busy LAN it grows back.' `
        'Disk Cleanup has a "Delivery Optimization Files" checkbox, or set the DO cache size by policy.' `
        -Where ($doPaths -join ' + ')

    $cbs = "$env:SystemRoot\Logs\CBS"
    Add-Finding 'cbs-logs' 'Servicing logs' (FolderMB $cbs) 'safe' 'updates' `
        'Component servicing logs.' 'You lose servicing history for past troubleshooting.' '' -Where $cbs

    # Panther holds setup logs from feature updates - and grows every upgrade.
    #
    # C:\Windows\inf IS NOT A LOG FOLDER. It is the driver INF store, and only the handful of
    # setupapi*.log files in it are logs. Measuring the whole folder counted 823 .inf and 711 .PNF
    # files (73.7 MB on the machine this was found on) as reclaimable, under a finding graded SAFE
    # and labelled with the folder path - so an admin acting on it would delete the driver store and
    # lose driver installation permanently. Exactly the failure this tool exists to prevent, in the
    # tool itself. Scope it to logs, and say so in the path.
    $panther = FolderMB "$env:SystemRoot\Panther"
    $panther += FolderMB "$env:SystemRoot\inf" -Ext @('.log', '.txt')
    Add-Finding 'panther' 'Setup logs (Panther)' $panther 'safe' 'updates' `
        'Logs written by Windows Setup during feature updates and driver installs.' `
        'You lose the record used to diagnose a past upgrade failure.' `
        'Only the *.log files in \inf count here - the .inf and .PNF files next to them are the driver store and must stay.' `
        -Where "$env:SystemRoot\Panther + $env:SystemRoot\inf\*.log"

}

# ---------------- caches ----------------
if (Want 'caches') {
    Set-Phase 'Application caches'
    $teams = 0
    foreach ($p in (Get-ChildItem 'C:\Users' -Directory)) {
        $teams += FolderMB (Join-Path $p.FullName 'AppData\Roaming\Microsoft\Teams')
        $teams += FolderMB (Join-Path $p.FullName 'AppData\Local\Packages\MSTeams_8wekyb3d8bbwe\LocalCache')
    }
    Add-Finding 'teams-cache' 'Teams cache' $teams 'safe' 'caches' `
        'Classic and new Teams per-user caches.' `
        'Rebuilt on next launch; first start is slower. Sign-in is preserved.' '' `
        -Where 'C:\Users\*\AppData\Roaming\Microsoft\Teams + \AppData\Local\Packages\MSTeams_8wekyb3d8bbwe\LocalCache'

    if (-not $Quick) {
        $br = 0
        foreach ($p in (Get-ChildItem 'C:\Users' -Directory)) {
            $br += FolderMB (Join-Path $p.FullName 'AppData\Local\Google\Chrome\User Data\Default\Cache')
            $br += FolderMB (Join-Path $p.FullName 'AppData\Local\Microsoft\Edge\User Data\Default\Cache')
            $br += FolderMB (Join-Path $p.FullName 'AppData\Local\Mozilla\Firefox\Profiles')
        }
        Add-Finding 'browser-cache' 'Browser caches' $br 'safe' 'caches' `
            'Chrome, Edge and Firefox disk caches.' `
            'None. Bookmarks, passwords, history and cookies are NOT in these folders.' '' `
            -Where 'C:\Users\*\AppData\Local\Google\Chrome\User Data\Default\Cache + \Microsoft\Edge\User Data\Default\Cache + \Mozilla\Firefox\Profiles'
    }
}

# ---------------- installer cache (the reason this tool exists) ----------------
if (Want 'installer') {
    Set-Phase 'Installer cache (slow - reads MSI metadata)'
    $cache = Join-Path $env:SystemRoot 'Installer'
    $cacheTotal = 0.0; $orphanMb = 0.0; $orphanCount = 0; $readable = $false
    $unknownMb = 0.0; $unknownCount = 0; $inUseCount = 0; $refCount = 0
    if (Test-Path -LiteralPath $cache) {
        $files = @(Get-ChildItem -LiteralPath $cache -File -Force | Where-Object { $_.Extension -in '.msi', '.msp' })
        foreach ($f in $files) { $cacheTotal += $f.Length / 1MB }

        $referenced = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
        foreach ($root in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData',
                            'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Installer\UserData')) {
            if (-not (Test-Path -LiteralPath $root)) { continue }
            foreach ($k in (Get-ChildItem -LiteralPath $root -Recurse)) {
                $lp = $k.GetValue('LocalPackage', $null); if ($lp) { [void]$referenced.Add([string]$lp) }
            }
        }
        $installed = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
        $msi = $null; try { $msi = New-Object -ComObject WindowsInstaller.Installer } catch { }
        if ($msi) {
            try {
                # InvokeMember, NOT $msi.Products - the PowerShell COM adapter returns the collection
                # OBJECT rather than enumerating it (measured 1 against the real 143), which would
                # make every cached file look orphaned. The most dangerous possible wrong answer.
                foreach ($p in @($msi.GetType().InvokeMember('Products','GetProperty',$null,$msi,$null))) {
                    $c = [string]$p; if ($c) { [void]$installed.Add($c) }
                }
            } catch { }
        }
        $readable = ($installed.Count -gt 0)
        if ($readable) {
            foreach ($f in $files) {
                if ($referenced.Contains($f.FullName)) { $refCount++; continue }
                $claimed = ''
                try {
                    # MEASURED, 2026-09-06: on both a workstation (283 cached files, 6.5 GB) and a
                    # client VM, EVERY .msp was resolved by the registry check above and none ever
                    # reached this branch. That matters because the branch is not right for patches:
                    # Summary Information property 9 on a patch starts with the PATCH code, not the
                    # ProductCode of the thing being patched, so comparing it against the installed
                    # ProductCodes cannot match and would call the patch orphaned. It is unexercised
                    # rather than correct. If a machine ever shows .msp files landing in the orphan
                    # bucket, this is why - read the target ProductCodes further along property 9
                    # instead of taking the first GUID. Do not "simplify" it before then.
                    if ($f.Extension -eq '.msp') {
                        $si = $msi.GetType().InvokeMember('SummaryInformation','GetProperty',$null,$msi,@($f.FullName,0))
                        $rev = [string]($si.GetType().InvokeMember('Property','GetProperty',$null,$si,@(9)))
                        if ($rev -match '(\{[0-9A-Fa-f\-]{36}\})') { $claimed = $Matches[1] }
                    } else {
                        $db = $msi.GetType().InvokeMember('OpenDatabase','InvokeMethod',$null,$msi,@($f.FullName,0))
                        $q = "SELECT ``Value`` FROM ``Property`` WHERE ``Property``='ProductCode'"
                        $vw = $db.GetType().InvokeMember('OpenView','InvokeMethod',$null,$db,@($q))
                        [void]$vw.GetType().InvokeMember('Execute','InvokeMethod',$null,$vw,$null)
                        $rec = $vw.GetType().InvokeMember('Fetch','InvokeMethod',$null,$vw,$null)
                        if ($rec) { $claimed = [string]($rec.GetType().InvokeMember('StringData','GetProperty',$null,$rec,@(1))) }
                    }
                } catch { $claimed = '' }
                # A package we cannot identify is NOT "in use" - it is unidentified, and those are
                # two different statements. Folding them together told a CLIENT3 user that 80 MB
                # was referenced by installed products when the truth was that the file would not
                # open. Fail closed (never call it reclaimable) but count it separately and say so.
                if ($claimed -notmatch '^\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}$') {
                    $unknownMb += $f.Length / 1MB; $unknownCount++; continue
                }
                if ($installed.Contains($claimed)) { $inUseCount++; continue }
                # KEEP THE PATHS, not just the total. -Apply must delete exactly the files this
                # loop proved are orphaned. Re-deriving the list later, or deleting by wildcard from
                # the folder, would throw away the one piece of work that makes this safe.
                $orphanMb += $f.Length / 1MB; $orphanCount++
                $script:orphanFiles += $f.FullName
            }
        } else { $notes += 'Could not read the installed product list, so installer-cache orphans were not identified. Run as administrator.' }
    }
    if ($readable) {
        Add-Finding 'installer-orphans' 'Installer cache - orphaned' $orphanMb 'safe' 'installer' `
            "$orphanCount of $($files.Count) cached packages, belonging to products that are no longer installed. Checked against both the installer database and the registry." `
            'None. These belong to software that is already gone.' `
            'Move them somewhere else rather than deleting, then check a repair still works on a few of the products that are left.' `
            -Where "$cache (the orphaned .msi/.msp files only)" 
    } else {
        Add-Finding 'installer-orphans' 'Installer cache - orphaned' 0 'leave' 'installer' `
            'Not determinable without administrator rights.' 'Nothing is claimed when only one of the two checks is available.' `
            '' -Where $cache
    }
    Add-Finding 'installer-inuse' 'Installer cache - in use' ($cacheTotal - $orphanMb - $unknownMb) 'leave' 'installer' `
        "$($refCount + $inUseCount) packages that installed products still reference." `
        'Deleting these breaks repair, modify and uninstall for those products. It usually gets noticed at the next patch or removal, not today.' `
        '' -Where $cache
    if ($unknownMb -ge 1) {
        Add-Finding 'installer-unknown' 'Installer cache - could not identify' $unknownMb 'unknown' 'installer' `
            "$unknownCount packages that would not open, so nothing is known about them either way." `
            'Unknown, which is the point. These are not counted as reclaimable and not claimed to be in use either. Most often a package that is damaged or ACL-locked.' `
            'Try opening one with msiexec or Orca as SYSTEM. If it is genuinely unreadable, treat it the way you would any file you cannot identify.' `
            -Where $cache
    }
}

# ---------------- dumps ----------------
if (Want 'dumps') {
    Set-Phase 'Crash dumps and error reports'
    $memDmp = "$env:SystemRoot\MEMORY.DMP"; $miniDmp = "$env:SystemRoot\Minidump"
    $werDir = "$env:ProgramData\Microsoft\Windows\WER"
    Add-Finding 'memory-dmp' 'Kernel memory dump' (FileMB $memDmp) 'safe' 'dumps' `
        'From the last bugcheck. Sized close to installed RAM.' `
        'You lose the crash dump. If you''re still chasing a blue screen, keep it.' '' -Where $memDmp
    Add-Finding 'minidumps' 'Minidumps' (FolderMB $miniDmp) 'safe' 'dumps' `
        'Small per-crash dumps.' 'Same as above: only matters if you''re still chasing a crash.' '' -Where $miniDmp
    Add-Finding 'wer' 'Error report queue' (FolderMB $werDir) 'safe' 'dumps' `
        'Windows Error Reporting queue and archive.' 'None in normal operation.' '' -Where $werDir
}

# ---------------- leftover install images ----------------
if (Want 'images') {
    Set-Phase 'Windows.old and upgrade staging'
    # ALWAYS emitted, even at zero. Omitting a finding when it measures 0 makes "checked, nothing
    # there" indistinguishable from "never checked" - and on a diagnostic tool that difference is
    # the whole product. Found on a domain controller where these two were silently absent while
    # every other zero was reported (2026-09-05).
    $winOld = 'C:\Windows.old'
    $wo = FolderMB $winOld
    Add-Finding 'windows-old' 'Previous Windows installation' $wo 'caution' 'images' `
        'Left by a feature update or in-place upgrade.' `
        'You lose the ability to roll back to the previous build. Windows removes it automatically after 10 days.' `
        'Use Disk Cleanup''s "Previous Windows installation(s)" - a plain delete leaves most of it behind on ACLs.' `
        -Where $winOld
    $btPaths = @('C:\$WINDOWS.~BT', 'C:\$WINDOWS.~WS', 'C:\$GetCurrent')
    $bt = 0; foreach ($d in $btPaths) { $bt += FolderMB $d }
    Add-Finding 'upgrade-staging' 'Upgrade staging folders' $bt 'caution' 'images' `
            'Left by a feature update - often by one that FAILED and rolled back.' `
            'Nothing if no upgrade is in flight. If one''s running or waiting on a reboot, removing these breaks it.' `
            'They''re SYSTEM-owned with tight ACLs, so a plain delete leaves most of the tree behind.' `
            -Where ($btPaths -join ' + ')
}

# ---------------- profiles ----------------
if ((Want 'profiles') -and -not $Quick) {
    $stale = @(); $staleMb = 0.0
    foreach ($p in (Get-ChildItem 'C:\Users' -Directory)) {
        if ($p.Name -in @('Public','Default','Default User','All Users')) { continue }
        $nt = Join-Path $p.FullName 'NTUSER.DAT'
        if (-not (Test-Path -LiteralPath $nt)) { continue }
        $last = (Get-Item -LiteralPath $nt -Force).LastWriteTime
        if ($last -lt (Get-Date).AddDays(-$StaleProfileDays)) {
            $mb = FolderMB $p.FullName; $staleMb += $mb
            $stale += [ordered]@{ name = $p.Name; lastUsed = $last.ToString('yyyy-MM-dd'); sizeMB = [math]::Round($mb,1) }
        }
    }
    # Name the actual profiles rather than the parent folder. "3 stale profiles in C:\Users" still
    # leaves the reader to work out WHICH three, and that is the step where the wrong one goes.
    $staleWhere = if ($stale.Count -eq 0) { 'C:\Users' }
                  elseif ($stale.Count -le 4) { (($stale | ForEach-Object { "C:\Users\$($_.name)" }) -join ' + ') }
                  else { (($stale | Select-Object -First 4 | ForEach-Object { "C:\Users\$($_.name)" }) -join ' + ') + " + $($stale.Count - 4) more" }
    Add-Finding 'stale-profiles' 'Stale user profiles' $staleMb 'caution' 'profiles' `
        "$($stale.Count) local profile(s) unused for more than $StaleProfileDays days." `
        'Anything the user left in their profile goes with it. Confirm they''ve actually gone.' `
        'Remove via the profile API (or RFF''s operation), never by deleting the folder - that orphans the registry entry.' `
        -Where $staleWhere
    $script:staleProfiles = $stale
}

# ---------------- system-managed ----------------
if (Want 'system') {
    Set-Phase 'System files, shadow copies, component store'
    $ram = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1MB, 0)
    # Same ACL trap as the pagefile. Fall back to "RAM x the configured fraction" when the file
    # cannot be measured but hibernation is clearly enabled, rather than silently reporting 0.
    $hibFile = 'C:\hiberfil.sys'
    $hibMb = FileMB $hibFile
    if ($hibMb -eq 0) {
        $hibOn = $false
        try { $hibOn = ((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Power' -Name HibernateEnabled -ErrorAction Stop).HibernateEnabled -eq 1) } catch { }
        if ($hibOn) {
            $pct = 40
            try { $pct = [int](Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Power' -Name HiberFileSizePercent -ErrorAction Stop).HiberFileSizePercent } catch { }
            if ($pct -le 0) { $pct = 40 }
            $hibMb = [math]::Round($ram * ($pct / 100.0), 0)
        }
    }
    Add-Finding 'hiberfil' 'Hibernation file' $hibMb 'caution' 'system' `
        'Sized against installed RAM.' `
        'Disabling hibernation also disables Fast Startup, and on laptops removes hibernate entirely.' `
        'powercfg /hibernate off removes it; powercfg /hibernate /size 40 shrinks it instead.' `
        -Where $hibFile

    # Asked of WINDOWS, not of the file system. Test-Path returns FALSE for C:\pagefile.sys even
    # elevated - its ACL denies the probe - so the file-based check reported 0 MB for a 48 GB file
    # on the machine this was written on. The single largest item on the drive, invisible. Locking
    # is not the cause: Get-Item reads other locked system files fine.
    $pfMb = 0.0; $pfWhere = ''
    foreach ($pf in (Get-CimInstance Win32_PageFileUsage -ErrorAction SilentlyContinue)) {
        $pfMb += [double]$pf.AllocatedBaseSize
        $pfWhere = $pf.Name
    }
    $autoPf = (Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue).AutomaticManagedPagefile
    Add-Finding 'pagefile' 'Page file' $pfMb 'leave' 'system' `
        "$(if ($autoPf) { 'System-managed size.' } else { 'Fixed size set by policy or by hand.' })" `
        'It isn''t a cache, and you can''t delete it while it''s in use. Shrinking or moving it changes how crash dumps and low memory behave, so treat it as tuning rather than cleanup.' `
        'If it''s fixed and oversized, change it under System Properties > Advanced > Performance > Virtual memory. Takes a reboot.' `
        -Where $(if ($pfWhere) { $pfWhere } else { 'C:\pagefile.sys' })

    # Shadow copies are routinely the single largest reclaimable item and almost nobody checks.
    $vssMb = 0.0; $vssNote = 'No shadow copy storage in use.'
    try {
        $v = & vssadmin list shadowstorage 2>&1
        $m = [regex]::Match(($v -join "`n"), 'Used Shadow Copy Storage space:\s*([\d\.,]+)\s*(MB|GB|TB)')
        if ($m.Success) {
            $val = [double]($m.Groups[1].Value -replace ',', '')
            $vssMb = switch ($m.Groups[2].Value) { 'GB' { $val * 1024 } 'TB' { $val * 1048576 } default { $val } }
            $vssNote = 'Shadow copy storage in use.'
        }
    } catch { }
    Add-Finding 'shadow-copies' 'Volume shadow copies' $vssMb 'caution' 'system' `
        "Restore points and VSS snapshots. $vssNote" `
        'You lose every System Restore point, and any backup product using VSS snapshots on this volume loses its history too.' `
        'vssadmin resize shadowstorage caps it without deleting everything - usually the better move.' `
        -Where 'Inside the C: volume - no folder to browse (vssadmin list shadowstorage)'

    if (-not $Quick) {
        $wsxNote = 'Not analysed.'; $wsxMb = 0.0
        try {
            $an = (& dism.exe /Online /Cleanup-Image /AnalyzeComponentStore 2>&1) -join "`n"
            if ($an -match 'Component Store Cleanup Recommended\s*:\s*Yes') { $wsxNote = 'DISM recommends a cleanup.' }
            elseif ($an) { $wsxNote = 'DISM does not currently recommend a cleanup.' }
            $m = [regex]::Match($an, 'Actual Size of Component Store\s*:\s*([\d\.]+)\s*(MB|GB)')
            if ($m.Success) { $v = [double]$m.Groups[1].Value; $wsxMb = if ($m.Groups[2].Value -eq 'GB') { $v * 1024 } else { $v } }
        } catch { }
        Add-Finding 'winsxs' 'Component store (WinSxS)' $wsxMb 'caution' 'system' `
            "Actual size of the component store. $wsxNote Don't go by the folder size in Explorer - WinSxS is mostly hard links." `
            'A cleanup with /ResetBase is IRREVERSIBLE - you can''t uninstall any update installed before it. Without /ResetBase it just drops superseded components and is safe.' `
            'DISM /Online /Cleanup-Image /StartComponentCleanup, and only add /ResetBase deliberately.' `
            -Where "$env:SystemRoot\WinSxS" 
    }
}

# ---------------- context ----------------
# Storage Sense lives in THREE places and the per-user one is the wrong place to look first.
#
# Reported wrongly on a managed enterprise machine (2026-09-06): Settings showed Storage Sense ON,
# this said OFF. It was enabled by Group Policy, which writes to HKLM and does not touch the
# per-user key at all - so the only key being read was legitimately absent.
#
# Order matters. Policy wins outright: when it is set the user cannot change it, so it is the
# answer regardless of what the per-user key says. Only when there is no policy does the per-user
# value decide.
#
# Third case, and it is not theoretical: HKCU is the hive of whoever the process is running as. Run
# this as SYSTEM, or elevated with a separate admin account (normal on a managed fleet), and HKCU
# belongs to that account rather than to the person signed in - so the per-user setting read is the
# wrong user's. Fall back to reading the signed-in user's hive directly under HKEY_USERS.
$ssOn = $null; $ssWhere = ''

try {
    $pol = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\StorageSense' -Name 'AllowStorageSenseGlobal' -ErrorAction Stop
    $ssOn = ([int]$pol.AllowStorageSenseGlobal -eq 1)
    $ssWhere = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\StorageSense\AllowStorageSenseGlobal (Group Policy)'
} catch { }

if ($null -eq $ssOn) {
    try {
        $u = Get-ItemProperty 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy' -Name '01' -ErrorAction Stop
        $ssOn = ([int]$u.'01' -eq 1)
        $ssWhere = 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy\01'
    } catch { }
}

if ($null -eq $ssOn) {
    # Whoever is actually signed in, which is not necessarily whoever this is running as.
    try {
        $consoleUser = (Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).UserName
        if ($consoleUser) {
            $sid = (New-Object System.Security.Principal.NTAccount($consoleUser)).Translate(
                   [System.Security.Principal.SecurityIdentifier]).Value
            $hive = "Registry::HKEY_USERS\$sid\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy"
            if (Test-Path -LiteralPath $hive) {
                $h = Get-ItemProperty -LiteralPath $hive -Name '01' -ErrorAction Stop
                $ssOn = ([int]$h.'01' -eq 1)
                $ssWhere = "HKEY_USERS\$sid\...\StoragePolicy\01 ($consoleUser)"
            }
        }
    } catch { }
}

# What Storage Sense ACTUALLY cleans, which is a much shorter list than the note used to imply.
# It handles the temp folders, the Recycle Bin, the Downloads folder if you tell it to, cloud
# content, and a previous Windows installation. It does not touch the component store, the
# installer cache, servicing or setup logs, crash dumps, error reports or shadow copies - so
# "turning it on prevents most of the safe list coming back" was overclaiming. On the machine that
# reported this, Settings said Storage Sense was ON and there was still 17 GB in the safe column,
# which is exactly what that wrong sentence failed to explain.
$ssCovers = @('win-temp', 'user-temp', 'recycle', 'windows-old')
$ssCoveredMb = 0.0; $ssUncoveredMb = 0.0
foreach ($f in $findings) {
    if ($f.confidence -ne 'safe') { continue }
    if ($ssCovers -contains $f.id) { $ssCoveredMb += [double]$f.sizeMB } else { $ssUncoveredMb += [double]$f.sizeMB }
}

if ($ssOn -eq $false) {
    $notes += ("Storage Sense is OFF (read from {0}). It would keep about {1:N0} MB of the safe list down on its own - the temp folders, the Recycle Bin and any previous Windows installation. The other {2:N0} MB is outside what it touches." -f $ssWhere, $ssCoveredMb, $ssUncoveredMb)
} elseif ($ssOn -eq $true -and $ssUncoveredMb -ge 500) {
    # The question the reporting machine actually raised: Storage Sense is on, so why is there
    # still a pile of reclaimable space? Because most of this list was never its job.
    $notes += ("Storage Sense is ON (read from {0}), and {1:N0} MB of the safe list is still outside what it cleans - it does not touch the component store, the installer cache, servicing and setup logs, crash dumps or error reports." -f $ssWhere, $ssUncoveredMb)
} elseif ($null -eq $ssOn) {
    # Say we could not tell rather than guessing OFF. Reporting a definite state we have not
    # established is how this got it wrong on a managed machine in the first place.
    $ssWhere = 'not found in policy, this user''s hive, or the signed-in user''s hive'
    $notes += 'Could not determine whether Storage Sense is on. Check Settings > System > Storage.'
}
if (-not $isAdmin) { $notes += 'Not running as administrator - servicing, shadow-copy and installer-cache figures may be incomplete.' }

$drive = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$($env:SystemDrive)'"
$sw.Stop()

# Summed with a loop, not Measure-Object: these are ordered hashtables and Measure-Object reads
# PROPERTIES, so it silently produced blank totals in the first version.
$safeMb = 0.0; $cautionMb = 0.0; $leaveMb = 0.0; $unknownMbTotal = 0.0
foreach ($f in $findings) {
    switch ($f.confidence) {
        'safe'    { $safeMb         += [double]$f.sizeMB }
        'caution' { $cautionMb      += [double]$f.sizeMB }
        'leave'   { $leaveMb        += [double]$f.sizeMB }
        'unknown' { $unknownMbTotal += [double]$f.sizeMB }
        # A grade with no arm here does not fail, it silently drops the megabytes from every total
        # and from the header, so the figures stop adding up to the folder with nothing to show why.
        default   { $notes += "Internal: grade '$($f.confidence)' on $($f.id) is not counted in any total." }
    }
}

Set-Phase 'Summarizing'
# Clear the bar before any output lands, or it sits on screen over the results.
Write-Progress -Activity 'Disk reclaim scan' -Completed

$snap = [ordered]@{
    schema = 'rff-disk-reclaim/2'; collectedAt = (Get-Date).ToUniversalTime().ToString('o')
    computer = $env:COMPUTERNAME; os = (Get-CimInstance Win32_OperatingSystem).Caption
    drive = $env:SystemDrive; totalGB = [math]::Round($drive.Size/1GB,1); freeGB = [math]::Round($drive.FreeSpace/1GB,1)
    isAdmin = $isAdmin; storageSenseOn = $ssOn; storageSenseSource = $ssWhere; quick = [bool]$Quick; scanSeconds = [int]$sw.Elapsed.TotalSeconds
    safeMB = [math]::Round($safeMb,1); cautionMB = [math]::Round($cautionMb,1); leaveMB = [math]::Round($leaveMb,1)
    unknownMB = [math]::Round($unknownMbTotal,1)
    findings = $findings; staleProfiles = @($script:staleProfiles); notes = $notes
}
# ============================================================================================
#  -Apply : do the removals the report just described
#
#  Three gates, and all of them have to be passed deliberately:
#    1. -Apply             ... absent, nothing is deleted, which is the default and always will be
#    2. confidence         ... safe only, unless -IncludeCaution. leave/unknown can NEVER be removed
#    3. ShouldProcess      ... ConfirmImpact High, so it prompts unless -Confirm:$false. -WhatIf
#                              walks the whole plan and touches nothing.
#
#  The number reported at the end is MEASURED free space before and after, not the sum of the
#  estimates. Those two differ for honest reasons - hard links, compression, files that were locked,
#  a service writing while we work - and quoting the estimate as if it were the result is how a tool
#  ends up claiming it freed 6 GB on a disk that gained 4.
# ============================================================================================

if ($Apply) {
    $driveBefore = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$env:SystemDrive'"
    $freeBeforeMB = [math]::Round($driveBefore.FreeSpace / 1MB, 1)

    $eligible = @()
    $refused  = @()
    foreach ($f in $findings) {
        if ([double]$f.sizeMB -le 0) { continue }
        if ($f.confidence -eq 'safe') { $eligible += $f; continue }
        if ($f.confidence -eq 'caution' -and $IncludeCaution) { $eligible += $f; continue }
        if ($f.confidence -eq 'caution') { $refused += "$($f.id) (needs -IncludeCaution)"; continue }
        # leave / unknown never become eligible, whatever switches are passed.
        $refused += "$($f.id) ($($f.confidence) - never removable)"
    }

    Write-Host ""
    Write-Host "  APPLY: $($eligible.Count) finding(s) eligible$(if($IncludeCaution){' (safe + caution)'}else{' (safe only)'})" -ForegroundColor Yellow
    if (-not $isAdmin) {
        Write-Host "  NOT ELEVATED - machine-wide paths will mostly fail. Re-run as administrator." -ForegroundColor Red
    }

    # Opened BEFORE the first delete, not after the last one - see Open-RemovalLog. -WhatIf walks
    # the plan without touching anything, so there is nothing to record.
    if (-not $WhatIfPreference -and -not $NoRemovalLog) { [void](Open-RemovalLog $ApplyLog 'console') }

    foreach ($f in $eligible) {
        $target = "$($f.name) ~$([int]$f.sizeMB) MB [$($f.confidence)]"
        if (-not $PSCmdlet.ShouldProcess($target, 'Remove')) { continue }

        Write-RemovalLog ''
        Write-RemovalLog ("-- {0} ({1})  estimated {2:N0} MB  [{3}]" -f $f.name, $f.id, [double]$f.sizeMB, $f.confidence)

        $beforeFreed  = $script:freedBytes
        $beforeRemoved = $script:removedCount
        $beforeSkipped = $script:skippedCount

        $handled = Invoke-ReclaimAction $f.id
        # 'external' means Windows did the deleting (DISM, the shell's recycle bin, powercfg), so
        # there are no bytes for us to attribute. Counting it as 0 and saying nothing made the
        # summary look like the action had failed.
        if ($handled -eq 'external') {
            Write-Host ("    OK {0,-20} {1,9}   done by Windows - bytes show in the volume delta, not here" -f $f.id, '-')
            Write-RemovalLog ("{0}  HANDED OFF TO WINDOWS - individual files are not listed here, the volume delta is the receipt" -f (Get-Date).ToString('HH:mm:ss'))
            $script:applyItems += [ordered]@{ id = $f.id; name = $f.name; action = 'external'; estimateMB = [double]$f.sizeMB; freedMB = 0; removed = 0; skipped = 0 }
            $script:externalIds += $f.id
            continue
        }
        if ($handled -eq 'none') {
            # An id with no action is NOT quietly skipped. Silence here would read as success and
            # the operator would believe space was reclaimed that never was.
            Write-Host ("    -- {0,-20} no automated action - left alone" -f $f.id) -ForegroundColor DarkGray
            Write-RemovalLog ("{0}  NO ACTION - reported only, nothing was touched" -f (Get-Date).ToString('HH:mm:ss'))
            $script:applyItems += [ordered]@{ id = $f.id; name = $f.name; action = 'none'; freedMB = 0; removed = 0; skipped = 0 }
            continue
        }

        $freedMB = [math]::Round(($script:freedBytes - $beforeFreed) / 1MB, 1)
        $rm = $script:removedCount - $beforeRemoved
        $sk = $script:skippedCount - $beforeSkipped
        Write-Host ("    OK {0,-20} {1,9:N1} MB   removed {2}, skipped {3}" -f $f.id, $freedMB, $rm, $sk)
        $script:applyItems += [ordered]@{
            id = $f.id; name = $f.name; action = 'removed'; estimateMB = [double]$f.sizeMB
            freedMB = $freedMB; removed = $rm; skipped = $sk
        }
    }

    foreach ($r in $refused) { Write-Host "    -- skipped $r" -ForegroundColor DarkGray }

    # Give the filesystem a moment; VSS and the recycle bin do not release instantly.
    Start-Sleep -Seconds 2
    $driveAfter = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$env:SystemDrive'"
    $freeAfterMB = [math]::Round($driveAfter.FreeSpace / 1MB, 1)
    $realGainMB  = [math]::Round($freeAfterMB - $freeBeforeMB, 1)
    # Summed by hand. $script:applyItems holds [ordered] hashtables, and Measure-Object -Property
    # reads PROPERTIES - a hashtable KEY is not one, so it silently returned 0 and the footer read
    # "ACTUAL GAIN: 3,425 MB (sum of what was deleted: 0 MB)" while every per-item line was correct.
    $estimateMB = 0.0
    foreach ($it in $script:applyItems) { $estimateMB += [double]$it.freedMB }
    $estimateMB = [math]::Round($estimateMB, 1)

    Write-Host ""
    # TWO NUMBERS, BOTH STATED. The sum of the deletes is what this script actually removed and is
    # counted file by file. The volume delta is what the operating system says changed, and it is
    # the one people quote - but it can disagree for reasons that have nothing to do with us:
    # shadow copies still holding the data, hard-linked files, something else writing at the same
    # time, or free-space reporting that simply does not move (measured on a Hyper-V differencing
    # disk, 2026-09-11: writing 200 MB with a forced flush moved reported free space by 0.8 MB).
    # Printing only the volume delta would have reported "0 MB freed" after correctly deleting 2 GB.
    Write-Host ("  REMOVED     : {0,10:N0} MB   counted file by file, {1} item(s)" -f $estimateMB, $script:removedCount) -ForegroundColor Green
    Write-Host ("  Volume free : {0,10:N0} MB  ->  {1:N0} MB   (delta {2:N0} MB)" -f $freeBeforeMB, $freeAfterMB, $realGainMB)
    # Direction matters, and the first version ignored it: after DISM freed 5 GB the note blamed
    # shadow copies for a gap that pointed the other way entirely.
    $divergence = [math]::Abs($realGainMB - $estimateMB)
    if ($divergence -ge 100) {
        if ($realGainMB -gt $estimateMB) {
            $why = "The drive gained {0:N0} MB MORE than this script counted." -f $divergence
            if ($script:externalIds.Count -gt 0) {
                $why += " Expected here: {0} deleted through Windows rather than through us, so those bytes were never ours to count." -f ($script:externalIds -join ', ')
            } else {
                $why += " Something else on the machine freed space while this ran."
            }
        } else {
            $why = ("The drive gained {0:N0} MB LESS than was removed. Usual causes: a shadow copy still holding the deleted data (vssadmin list shadowstorage), hard-linked files another path still references, something else writing while this ran, or a virtual disk whose free-space reporting lags." -f $divergence)
        }
        Write-Host ("  " + $why) -ForegroundColor DarkYellow
    }
    if ($script:skippedCount -gt 0) {
        Write-Host ("  {0} item(s) could not be removed - in use, or access denied. Normal on a running system." -f $script:skippedCount) -ForegroundColor DarkGray
    }

    $applyRecord = [ordered]@{
        schema = 'rff-disk-reclaim-apply/1'; appliedAt = (Get-Date).ToUniversalTime().ToString('o')
        computer = $env:COMPUTERNAME; includedCaution = [bool]$IncludeCaution; wasAdmin = $isAdmin
        freeBeforeMB = $freeBeforeMB; freeAfterMB = $freeAfterMB; actualGainMB = $realGainMB
        deletedSumMB = $estimateMB; removedCount = $script:removedCount; skippedCount = $script:skippedCount
        items = $script:applyItems; refused = $refused
    }
    if ($WhatIfPreference) {
        Write-Host "  -WhatIf: no removal log written, because nothing was removed." -ForegroundColor DarkGray
    } elseif ($NoRemovalLog) {
        Write-Host "  Removal log SUPPRESSED (-NoRemovalLog). Nothing on disk records what was deleted." -ForegroundColor DarkYellow
    } else {
        Write-RemovalLog ''
        Write-RemovalLog ("{0}  TOTAL  deleted {1:N0} files, {2:N1} MB counted   {3} locked or denied" -f (Get-Date).ToString('HH:mm:ss'), $script:removedCount, $estimateMB, $script:skippedCount)
        Write-RemovalLog ("           volume free {0:N0} MB -> {1:N0} MB  (delta {2:N0} MB)" -f $freeBeforeMB, $freeAfterMB, $realGainMB)
        foreach ($r in $refused) { Write-RemovalLog ("           not eligible: {0}" -f $r) }
        Close-RemovalLog
        Write-Host "  Removal log : $ApplyLog  (appended - every run is in there)"
    }

    $snap.applied = $applyRecord
}

# NOT -Compress. This is the machine-readable half, but the person who opens it is usually a human
# checking one number, and a 60 KB single line in Notepad is no use to them. Indented costs a few
# extra KB and parses identically.
[System.IO.File]::WriteAllText($OutFile, ($snap | ConvertTo-Json -Depth 6), [System.Text.UTF8Encoding]::new($false))

if ($Gui) {
    Add-Type -AssemblyName System.Windows.Forms, System.Drawing
    $form = New-Object Windows.Forms.Form
    $form.Text = "Disk reclaim report - $($snap.computer)"
    # 940x620 was too small: the Cost column is the point of the window and it was the column that
    # got squeezed, the footnote about Storage Sense was cut off mid-sentence, and the last row sat
    # under the button bar. Size to the screen instead of a guess - 80% of the working area, capped
    # so it stays sane on an ultrawide, with a minimum that keeps all five columns readable.
    $wa = [Windows.Forms.Screen]::PrimaryScreen.WorkingArea
    $w  = [Math]::Min([int]($wa.Width  * 0.90), 1800)
    $h  = [Math]::Min([int]($wa.Height * 0.90), 1200)
    $form.Size = New-Object Drawing.Size($w, $h)
    $form.MinimumSize = New-Object Drawing.Size(1100, 700)
    $form.StartPosition = 'CenterScreen'

    $hdr = New-Object Windows.Forms.Label
    $hdr.Text = "$($snap.drive)  $($snap.freeGB) GB free of $($snap.totalGB) GB" +
                "     SAFE $([int]$snap.safeMB) MB     WITH CARE $([int]$snap.cautionMB) MB     IN USE $([int]$snap.leaveMB) MB" +
                $(if ($snap.unknownMB -ge 1) { "     UNKNOWN $([int]$snap.unknownMB) MB" } else { '' })
    $hdr.Dock = 'Top'; $hdr.Height = 34; $hdr.Font = New-Object Drawing.Font('Segoe UI', 10, [Drawing.FontStyle]::Bold)
    $hdr.TextAlign = 'MiddleLeft'; $form.Controls.Add($hdr)

    $grid = New-Object Windows.Forms.DataGridView
    $grid.Dock = 'Fill'; $grid.ReadOnly = $true; $grid.AllowUserToAddRows = $false
    $grid.AutoSizeColumnsMode = 'Fill'; $grid.RowHeadersVisible = $false; $grid.SelectionMode = 'FullRowSelect'
    # Wrap the cost text instead of clipping it to one line. The detail is the POINT of the column -
    # "a cleanup with /ResetBase is IRREVERS..." with the consequence cut off is worse than no
    # sentence, because it reads as advice while withholding the reason for it.
    $grid.DefaultCellStyle.WrapMode = 'True'
    $grid.AutoSizeRowsMode = 'AllCells'
    # AutoSizeRowsMode covers the DATA rows and leaves the HEADER row at a fixed default height, so
    # on a high-DPI display the column titles were clipped through the middle of the letters while
    # every row under them was fine. Size the header to its content too, and let it grow.
    $grid.ColumnHeadersHeightSizeMode = 'AutoSize'
    $grid.ColumnHeadersDefaultCellStyle.WrapMode = 'True'
    $grid.ColumnHeadersDefaultCellStyle.Padding = New-Object Windows.Forms.Padding(2, 4, 2, 4)
    # Location first. Everything else on the row is commentary on a path, so leading with the number
    # or the grade means the reader still has to hunt for the thing being talked about.
    $grid.ColumnCount = 5
    $grid.Columns[0].Name = 'Location';   $grid.Columns[0].FillWeight = 31
    $grid.Columns[1].Name = 'What';       $grid.Columns[1].FillWeight = 15
    $grid.Columns[2].Name = 'Size (MB)';  $grid.Columns[2].FillWeight = 8
    $grid.Columns[3].Name = 'Confidence'; $grid.Columns[3].FillWeight = 10
    $grid.Columns[4].Name = 'Cost if you remove it'; $grid.Columns[4].FillWeight = 36
    # Readability beats density here. The default ~8.25pt was fine on the machine this was written
    # on and hard to read on a larger, higher-resolution screen - and the Cost column is prose the
    # operator is meant to actually read before deleting anything, not a number to glance at.
    $grid.DefaultCellStyle.Font = New-Object Drawing.Font('Segoe UI', 10.5)
    $grid.ColumnHeadersDefaultCellStyle.Font = New-Object Drawing.Font('Segoe UI', 10.5, [Drawing.FontStyle]::Bold)
    $grid.Columns[0].DefaultCellStyle.Font = New-Object Drawing.Font('Consolas', 9.75)
    # The header legend says SAFE / WITH CARE / IN USE. The rows said safe / caution / leave, so one
    # window taught two vocabularies for the same three grades and the internal word 'leave' leaked
    # to the user. Same words in both places; the internal name stays internal.
    $label = @{ 'safe' = 'SAFE'; 'caution' = 'WITH CARE'; 'leave' = 'IN USE'; 'unknown' = 'UNKNOWN' }

    # GRADE FIRST, size second. Sorting purely by size put the page file at the top of the window -
    # the single largest number on the machine and the one thing the reader can do nothing about.
    # Everything actionable started below the fold. Now the list reads top-down as a work queue:
    # what you can remove, then what costs you something, then what to leave alone.
    $rank = @{ 'safe' = 0; 'caution' = 1; 'unknown' = 2; 'leave' = 3 }
    $ordered = $findings | Sort-Object `
        @{ Expression = { if ($rank.ContainsKey($_.confidence)) { $rank[$_.confidence] } else { 9 } } }, `
        @{ Expression = { -[double]$_.sizeMB } }

    foreach ($f in $ordered) {
        $shown = $(if ($label.ContainsKey($f.confidence)) { $label[$f.confidence] } else { $f.confidence })
        $i = $grid.Rows.Add($f.location, $f.name, ('{0:N1}' -f $f.sizeMB), $shown, $f.cost)
        $grid.Rows[$i].Cells[0].ToolTipText = $f.location
        $grid.Rows[$i].Cells[4].ToolTipText = $f.what + $(if ($f.how) { "`n`n" + $f.how } else { '' })
        switch ($f.confidence) {
            'safe'    { $grid.Rows[$i].DefaultCellStyle.BackColor = [Drawing.Color]::FromArgb(233,252,238) }
            'caution' { $grid.Rows[$i].DefaultCellStyle.BackColor = [Drawing.Color]::FromArgb(255,247,224) }
            'leave'   { $grid.Rows[$i].DefaultCellStyle.BackColor = [Drawing.Color]::FromArgb(242,242,245) }
            'unknown' { $grid.Rows[$i].DefaultCellStyle.BackColor = [Drawing.Color]::FromArgb(235,242,252) }
        }
    }
    $form.Controls.Add($grid); $grid.BringToFront()
    # DataGridView selects row 0 on show, and the selection highlight covers that row's grade
    # colour - so the single largest finding was the one row whose colour you could not see.
    # Clearing it before the form is shown does NOT hold: the grid re-establishes a current cell
    # when it is added and shown, so this has to happen in Shown, and CurrentCell has to go too or
    # ClearSelection just paints it again.
    $form.Add_Shown({
        $grid.CurrentCell = $null; $grid.ClearSelection()
        # Shrink to fit the rows. Sizing to 85% of the screen is right when a machine has thirty
        # findings and wrong when it has fifteen - the leftover was a slab of empty grid under the
        # last row. Row heights are only real once the grid has laid out, so this has to be in Shown.
        $rowsH = 0
        foreach ($r in $grid.Rows) { $rowsH += $r.Height }
        $needed = $rowsH + $grid.ColumnHeadersHeight + $hdr.Height + $foot.Height + $bar.Height + 64
        # CLAMP to the minimum, do not bail out at it. The first version required
        # needed >= MinimumSize and otherwise left the window alone - so a short list (needed ~620,
        # minimum 700) skipped the shrink entirely and kept the full 1200px height with 600px of
        # empty grid under the last row, which is the exact thing this was added to fix.
        $target = [Math]::Max($needed, $form.MinimumSize.Height)
        if ($target -lt $form.Height) {
            $form.Height = $target
            $form.Top = [Math]::Max(0, [int](([Windows.Forms.Screen]::PrimaryScreen.WorkingArea.Height - $target) / 2))
        }
    })

    $foot = New-Object Windows.Forms.Label
    # "Nothing was deleted - this only reports" stopped being true the moment the window grew a
    # button that deletes. Say what is true NOW and what the button will do, rather than a sentence
    # that contradicts the control sitting six inches below it.
    # Name the two files by what they are FOR, not by their extension. "JSON:" next to a dialog that
    # says "logged to ...removed.log" reads as two names for one file, and the operator has to work
    # out which one is which at the worst possible moment.
    $foot.Text = "Nothing has been deleted yet. The button below removes the SAFE rows only, unless you tick WITH CARE." +
                 "   This scan: $OutFile   |   If you remove, every file is logged to: $ApplyLog" +
                 $(if ($notes) { '   |   ' + ($notes -join '  ') } else { '' })
    # The Storage Sense note is two or three sentences and it was being clipped mid-word at 34px on
    # one line. It explains why the safe list is bigger than what Windows cleans on its own, which is
    # the whole justification for the tool - so it gets the room to be read.
    $foot.Dock = 'Bottom'; $foot.TextAlign = 'TopLeft'
    $foot.Padding = New-Object Windows.Forms.Padding(6, 4, 6, 4)
    $foot.Font = New-Object Drawing.Font('Segoe UI', 10)
    # MEASURE the note instead of guessing a height. A fixed 58px fitted the text on one machine and
    # clipped the last line on another - font scaling and DPI decide how many lines it wraps to, and
    # the sentence that gets cut is the one explaining why the safe list is bigger than what Storage
    # Sense cleans.
    #
    # Graphics come from a STATIC MeasureString on a throwaway bitmap, not $form.CreateGraphics().
    # The form has no window handle until it is shown, so CreateGraphics here threw and the whole
    # GUI never appeared - a layout tweak that cost the entire window.
    $foot.Height = 72
    try {
        $bmp = New-Object Drawing.Bitmap(1, 1)
        $g   = [Drawing.Graphics]::FromImage($bmp)
        $sz  = $g.MeasureString($foot.Text, $foot.Font, [Math]::Max(400, $w - 40))
        $foot.Height = [int]$sz.Height + 24
        $g.Dispose(); $bmp.Dispose()
    } catch { }
    $form.Controls.Add($foot)

    # ---- the delete side of the window -------------------------------------------------------
    #
    # Same eligibility rules as the -Apply command line, and the same Invoke-ReclaimAction behind
    # the button. A GUI that grew its own idea of what is removable is how the two paths drift
    # until one of them deletes something the other calls IN USE.
    #
    # SAFE ONLY by default, with WITH CARE behind a separate tick. That mirrors -IncludeCaution
    # being a second switch rather than part of -Apply: each caution item costs the operator
    # something real and the grid states what, so it should take a second decision, not a longer
    # click. IN USE and UNKNOWN are never eligible here, exactly as on the command line.
    # FlowLayoutPanel, not absolute Points. The first version pinned the button at x=250 and the
    # checkbox was AutoSize - its label ran past 250 and the button sat ON TOP of the text. A flow
    # layout cannot overlap by construction, and it survives the user resizing the window.
    $bar = New-Object Windows.Forms.FlowLayoutPanel
    # Taller to match the larger control font below; a 52px bar clipped a 10.5pt button.
    $bar.Dock = 'Bottom'; $bar.Height = 60; $bar.FlowDirection = 'LeftToRight'
    $bar.Font = New-Object Drawing.Font('Segoe UI', 10.5)
    $bar.WrapContents = $false
    $bar.Padding = New-Object Windows.Forms.Padding(10, 10, 10, 6)

    $chkCaution = New-Object Windows.Forms.CheckBox
    $chkCaution.Text = 'also remove WITH CARE items'
    $chkCaution.AutoSize = $true
    $chkCaution.Margin = New-Object Windows.Forms.Padding(2, 8, 24, 0)

    # Ticked unless -NoRemovalLog was passed, so the command line and the window agree on the
    # default rather than the GUI quietly having its own.
    $chkLog = New-Object Windows.Forms.CheckBox
    $chkLog.Text = 'write removal log'
    $chkLog.Checked = -not $NoRemovalLog
    $chkLog.AutoSize = $true
    $chkLog.Margin = New-Object Windows.Forms.Padding(2, 8, 24, 0)

    $btnApply = New-Object Windows.Forms.Button
    $btnApply.AutoSize = $true
    $btnApply.AutoSizeMode = 'GrowAndShrink'
    $btnApply.Height = 30
    $btnApply.Padding = New-Object Windows.Forms.Padding(14, 0, 14, 0)
    $btnApply.Margin = New-Object Windows.Forms.Padding(0, 3, 20, 0)

    $lblResult = New-Object Windows.Forms.Label
    $lblResult.AutoSize = $true
    $lblResult.Margin = New-Object Windows.Forms.Padding(0, 9, 0, 0)

    # One place decides what is eligible, so the button text and the action can never disagree.
    $eligibleNow = {
        $inc = $chkCaution.Checked
        @($findings | Where-Object {
            [double]$_.sizeMB -gt 0 -and
            ($_.confidence -eq 'safe' -or ($inc -and $_.confidence -eq 'caution'))
        })
    }
    # Findings are ORDERED HASHTABLES, not objects. `Measure-Object sizeMB -Sum` looks for a
    # PROPERTY of that name, a hashtable has none, and it silently sums nothing - the button read
    # "Reclaim 8 items - 0 MB" while pointing at 5,470 MB. Cast each value the way the rest of the
    # script already does.
    $sumMb = { param($items) [int](($items | ForEach-Object { [double]$_.sizeMB } | Measure-Object -Sum).Sum) }

    $refreshBtn = {
        $e = & $eligibleNow
        $mb = & $sumMb $e
        # "Remove", not "Reclaim". Reclaim is the marketing word for the outcome; the button does a
        # delete and should say so, because it is the last thing read before files go.
        $btnApply.Text = "Remove $($e.Count) item$(if($e.Count -eq 1){''}else{'s'})  -  $mb MB"
        $btnApply.Enabled = ($e.Count -gt 0)
    }
    $chkCaution.Add_CheckedChanged($refreshBtn)

    $btnApply.Add_Click({
        $e  = & $eligibleNow
        $mb = & $sumMb $e
        $names = ($e | Sort-Object { -[double]$_.sizeMB } | Select-Object -First 8 |
                  ForEach-Object { "  - $($_.name)  ~$([int]$_.sizeMB) MB" }) -join "`n"
        if ($e.Count -gt 8) { $names += "`n  ... and $($e.Count - 8) more" }

        $warn = if (-not $isAdmin) {
            "`n`nNOT RUNNING AS ADMINISTRATOR - machine-wide paths will mostly fail. Close this and re-run elevated for the full result."
        } else { '' }

        # Say which of the two it is. Promising a record and not writing one is the bug this whole
        # block already had once.
        $logLine = if ($chkLog.Checked) {
            "Every file removed is logged, one line each, to:`n$ApplyLog"
        } else {
            "NO RECORD WILL BE WRITTEN - nothing on disk will say what was deleted."
        }
        $ans = [Windows.Forms.MessageBox]::Show(
            "Remove $($e.Count) item(s), about $mb MB?`n`n$names`n`n$logLine$warn",
            'Confirm removal',
            [Windows.Forms.MessageBoxButtons]::YesNo,
            [Windows.Forms.MessageBoxIcon]::Warning,
            [Windows.Forms.MessageBoxDefaultButton]::Button2)   # default NO
        if ($ans -ne [Windows.Forms.DialogResult]::Yes) { return }

        $form.Cursor = [Windows.Forms.Cursors]::WaitCursor
        $btnApply.Enabled = $false; $chkCaution.Enabled = $false
        $freeBefore = (Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$env:SystemDrive'").FreeSpace

        # WRITE THE REMOVAL LOG. The confirmation dialog above promises "a record of exactly what was
        # removed is written to $ApplyLog" - and the writer lived inside the -Apply block, which the
        # GUI path does not run. So the button deleted files and wrote nothing, while telling the
        # operator otherwise. A destructive action that lies about its own audit trail is worse than
        # one that never offered it. Opened here, BEFORE the loop, so the per-file lines land as they
        # happen rather than being reconstructed afterwards.
        $logOpen = $false
        if ($chkLog.Checked) { $logOpen = Open-RemovalLog $ApplyLog 'gui' }
        if ($chkLog.Checked -and -not $logOpen) {
            [Windows.Forms.MessageBox]::Show(
                "The removal log could not be opened:`n$ApplyLog`n`nNothing has been deleted. Close this, fix the path or untick the log box, and try again.",
                'Removal log not written', [Windows.Forms.MessageBoxButtons]::OK,
                [Windows.Forms.MessageBoxIcon]::Warning) | Out-Null
            $form.Cursor = [Windows.Forms.Cursors]::Default
            $btnApply.Enabled = $true; $chkCaution.Enabled = $true
            return
        }

        # Say plainly that it is working and that a pause is expected, BEFORE the first delete. A
        # blank window that has stopped repainting reads as crashed, and the response to "crashed
        # while deleting" is to kill it, which is the one outcome worth engineering against.
        $foot.ForeColor = [Drawing.Color]::FromArgb(146,64,14)
        $foot.Text = "Working. Removing files now - please don't close this window. Some folders hold tens of thousands of small files, so a step can sit for a minute or two with nothing visibly happening. That's normal."
        $lblResult.ForeColor = [Drawing.Color]::FromArgb(146,64,14)
        $lblResult.Text = 'Starting...'
        $form.Refresh()

        $done = 0
        foreach ($f in $e) {
            Write-RemovalLog ''
            Write-RemovalLog ("-- {0} ({1})  estimated {2:N0} MB  [{3}]" -f $f.name, $f.id, [double]$f.sizeMB, $f.confidence)

            $done++
            $lblResult.Text = "$done of $($e.Count): $($f.name)..."
            # Yield once per finding AND every 25 files inside it (see Signal-Progress). Without the
            # inner one, a single 1.8 GB cache of small files still hangs the window for minutes.
            $script:onProgress = {
                param($p)
                $lblResult.Text = "$done of $($e.Count): $($f.name) - $($script:removedCount) files removed"
                [Windows.Forms.Application]::DoEvents()
            }.GetNewClosure()
            [Windows.Forms.Application]::DoEvents()

            [void](Invoke-ReclaimAction $f.id)
        }
        $script:onProgress = $null
        $lblResult.Text = 'Measuring free space...'
        [Windows.Forms.Application]::DoEvents()
        $freeAfter = (Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$env:SystemDrive'").FreeSpace

        if ($logOpen) {
            Write-RemovalLog ''
            Write-RemovalLog ("{0}  TOTAL  deleted {1:N0} files   {2} locked or denied" -f (Get-Date).ToString('HH:mm:ss'), $script:removedCount, $script:skippedCount)
            Write-RemovalLog ("           volume free {0:N0} MB -> {1:N0} MB  (delta {2:N0} MB)" -f ($freeBefore / 1MB), ($freeAfter / 1MB), (($freeAfter - $freeBefore) / 1MB))
            Close-RemovalLog
        }

        # Report the DRIVE delta, not the sum of what we hoped to remove. Some actions hand the work
        # to Windows (DISM, the shell) and finish later or partially, and a total that assumes every
        # byte went is the kind of number that gets quoted back at you.
        $gained = [math]::Round(($freeAfter - $freeBefore) / 1MB)
        $lblResult.Text = "Freed $gained MB. Re-run the scan to see the new picture."
        $lblResult.ForeColor = [Drawing.Color]::FromArgb(22,101,52)
        $foot.ForeColor = [Drawing.Color]::FromArgb(51,65,85)
        # The locked count is not a failure and the wording should not imply one. On a running system
        # some temp files are always open, and an operator who reads "12 failed" goes looking for a
        # problem that is not there.
        $locked = if ($script:skippedCount -gt 0) { "  $($script:skippedCount) file(s) were in use and left alone - normal on a running system." } else { '' }
        $foot.Text = if ($chkLog.Checked) { "Done. Removed $($script:removedCount) file(s) across $($e.Count) item(s).$locked  Full list: $ApplyLog" }
                     else { "Done. Removed $($script:removedCount) file(s) across $($e.Count) item(s).$locked  No removal log was written." }
        $form.Cursor = [Windows.Forms.Cursors]::Default
        $btnApply.Text = 'Done'
    })

    # Closing mid-delete is now REACHABLE, because the loop pumps the message queue to stay
    # responsive - which also means the X button works while files are going. Disposing the form
    # there would leave the loop writing to dead controls and the log half-written. Refuse the close
    # and say why; there is no safe cancel to offer, since a half-finished delete is still a delete.
    $script:busyRemoving = $false
    $form.Add_FormClosing({
        param($s, $ev)
        if (-not $script:busyRemoving) { return }
        $ev.Cancel = $true
        [Windows.Forms.MessageBox]::Show(
            "Still removing files. Closing now would stop it part-way and leave the removal log incomplete.`n`nIt will finish on its own - the window unlocks when it does.",
            'Still working', [Windows.Forms.MessageBoxButtons]::OK,
            [Windows.Forms.MessageBoxIcon]::Information) | Out-Null
    })

    $bar.Controls.AddRange(@($chkCaution, $chkLog, $btnApply, $lblResult))
    $form.Controls.Add($bar)
    & $refreshBtn

    [void]$form.ShowDialog()
} else {
    Write-Host ""
    Write-Host "  $($snap.computer)  $($snap.drive)  $($snap.freeGB) GB free of $($snap.totalGB) GB"
    Write-Host ""
    foreach ($f in ($findings | Sort-Object { -[double]$_.sizeMB })) {
        if ([double]$f.sizeMB -lt 1) { continue }
        # Same three words the summary below uses. Padded to a common width so the column still
        # lines up - the GUI had the same split vocabulary and it was no better here.
        $tag = switch ($f.confidence) { 'safe' { 'SAFE     ' } 'caution' { 'WITH CARE' } 'unknown' { 'UNKNOWN  ' } default { 'IN USE   ' } }
        Write-Host ("  {0} {1,10:N1} MB  {2}" -f $tag, $f.sizeMB, $f.name)
        # On its own line: paths are long and wrapping them into the size column makes the whole
        # list unreadable. Indented so it stays visibly attached to the row above it.
        if ($f.location) { Write-Host ("  {0,-9} {1,10}     {2}" -f '', '', $f.location) -ForegroundColor DarkGray }
    }
    Write-Host ""
    Write-Host ("  SAFE to reclaim   : {0,10:N0} MB" -f $safeMb)
    Write-Host ("  RECLAIM WITH CARE : {0,10:N0} MB   (each has a stated cost)" -f $cautionMb)
    Write-Host ("  IN USE, leave     : {0,10:N0} MB" -f $leaveMb)
    if ($unknownMbTotal -ge 1) { Write-Host ("  UNKNOWN           : {0,10:N0} MB   (not claimed either way)" -f $unknownMbTotal) }
    foreach ($n in $notes) { Write-Host "  NOTE: $n" }
    Write-Host ""
    Write-Host "  Wrote $OutFile  (scan took $($snap.scanSeconds)s)"
    if ($Apply -and -not $WhatIfPreference) {
        Write-Host "  Files were REMOVED. See $ApplyLog for exactly what."
    } elseif ($Apply) {
        Write-Host "  -WhatIf: nothing was touched. That was the plan, not the result."
    } else {
        Write-Host "  Nothing was deleted. This script only reports."
        Write-Host "  Add -Apply to remove the safe list. -WhatIf shows the plan; -Force skips the prompt for unattended runs." -ForegroundColor DarkGray
    }
}

# -- Exit code, so a scheduler or an RMM can act without parsing the text above -------------------
#
# Reported, never acted on: this script does not reboot anything. 3010 is the standard "succeeded,
# needs a restart to finish" value that every deployment tool already understands, which is why it
# is reused here rather than inventing one.
if ($script:componentCleanupTimedOut) {
    Write-Host ("  Component cleanup exceeded {0} minutes and was stopped. Nothing else was affected." -f $ComponentCleanupTimeoutMins) -ForegroundColor DarkYellow
}
if ($script:needsReboot) {
    Write-Host "  A restart is needed to finish the component store cleanup. This script will not reboot anything." -ForegroundColor Yellow
    $script:exitCode = 3010
}
exit $script:exitCode

# SIG # Begin signature block
# MIIs4AYJKoZIhvcNAQcCoIIs0TCCLM0CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAwKonk1KCCmJYe
# G3jg6GEbz0UdfPzmoK6S8W2g98pOdqCCJfQwggVvMIIEV6ADAgECAhBI/JO0YFWU
# jTanyYqJ1pQWMA0GCSqGSIb3DQEBDAUAMHsxCzAJBgNVBAYTAkdCMRswGQYDVQQI
# DBJHcmVhdGVyIE1hbmNoZXN0ZXIxEDAOBgNVBAcMB1NhbGZvcmQxGjAYBgNVBAoM
# EUNvbW9kbyBDQSBMaW1pdGVkMSEwHwYDVQQDDBhBQUEgQ2VydGlmaWNhdGUgU2Vy
# dmljZXMwHhcNMjEwNTI1MDAwMDAwWhcNMjgxMjMxMjM1OTU5WjBWMQswCQYDVQQG
# EwJHQjEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMS0wKwYDVQQDEyRTZWN0aWdv
# IFB1YmxpYyBDb2RlIFNpZ25pbmcgUm9vdCBSNDYwggIiMA0GCSqGSIb3DQEBAQUA
# A4ICDwAwggIKAoICAQCN55QSIgQkdC7/FiMCkoq2rjaFrEfUI5ErPtx94jGgUW+s
# hJHjUoq14pbe0IdjJImK/+8Skzt9u7aKvb0Ffyeba2XTpQxpsbxJOZrxbW6q5KCD
# J9qaDStQ6Utbs7hkNqR+Sj2pcaths3OzPAsM79szV+W+NDfjlxtd/R8SPYIDdub7
# P2bSlDFp+m2zNKzBenjcklDyZMeqLQSrw2rq4C+np9xu1+j/2iGrQL+57g2extme
# me/G3h+pDHazJyCh1rr9gOcB0u/rgimVcI3/uxXP/tEPNqIuTzKQdEZrRzUTdwUz
# T2MuuC3hv2WnBGsY2HH6zAjybYmZELGt2z4s5KoYsMYHAXVn3m3pY2MeNn9pib6q
# RT5uWl+PoVvLnTCGMOgDs0DGDQ84zWeoU4j6uDBl+m/H5x2xg3RpPqzEaDux5mcz
# mrYI4IAFSEDu9oJkRqj1c7AGlfJsZZ+/VVscnFcax3hGfHCqlBuCF6yH6bbJDoEc
# QNYWFyn8XJwYK+pF9e+91WdPKF4F7pBMeufG9ND8+s0+MkYTIDaKBOq3qgdGnA2T
# OglmmVhcKaO5DKYwODzQRjY1fJy67sPV+Qp2+n4FG0DKkjXp1XrRtX8ArqmQqsV/
# AZwQsRb8zG4Y3G9i/qZQp7h7uJ0VP/4gDHXIIloTlRmQAOka1cKG8eOO7F/05QID
# AQABo4IBEjCCAQ4wHwYDVR0jBBgwFoAUoBEKIz6W8Qfs4q8p74Klf9AwpLQwHQYD
# VR0OBBYEFDLrkpr/NZZILyhAQnAgNpFcF4XmMA4GA1UdDwEB/wQEAwIBhjAPBgNV
# HRMBAf8EBTADAQH/MBMGA1UdJQQMMAoGCCsGAQUFBwMDMBsGA1UdIAQUMBIwBgYE
# VR0gADAIBgZngQwBBAEwQwYDVR0fBDwwOjA4oDagNIYyaHR0cDovL2NybC5jb21v
# ZG9jYS5jb20vQUFBQ2VydGlmaWNhdGVTZXJ2aWNlcy5jcmwwNAYIKwYBBQUHAQEE
# KDAmMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5jb21vZG9jYS5jb20wDQYJKoZI
# hvcNAQEMBQADggEBABK/oe+LdJqYRLhpRrWrJAoMpIpnuDqBv0WKfVIHqI0fTiGF
# OaNrXi0ghr8QuK55O1PNtPvYRL4G2VxjZ9RAFodEhnIq1jIV9RKDwvnhXRFAZ/ZC
# J3LFI+ICOBpMIOLbAffNRk8monxmwFE2tokCVMf8WPtsAO7+mKYulaEMUykfb9gZ
# pk+e96wJ6l2CxouvgKe9gUhShDHaMuwV5KZMPWw5c9QLhTkg4IUaaOGnSDip0TYl
# d8GNGRbFiExmfS9jzpjoad+sPKhdnckcW67Y8y90z7h+9teDnRGWYpquRRPaf9xH
# +9/DUp/mBlXpnYzyOmJRvOwkDynUWICE5EV7WtgwggYaMIIEAqADAgECAhBiHW0M
# UgGeO5B5FSCJIRwKMA0GCSqGSIb3DQEBDAUAMFYxCzAJBgNVBAYTAkdCMRgwFgYD
# VQQKEw9TZWN0aWdvIExpbWl0ZWQxLTArBgNVBAMTJFNlY3RpZ28gUHVibGljIENv
# ZGUgU2lnbmluZyBSb290IFI0NjAeFw0yMTAzMjIwMDAwMDBaFw0zNjAzMjEyMzU5
# NTlaMFQxCzAJBgNVBAYTAkdCMRgwFgYDVQQKEw9TZWN0aWdvIExpbWl0ZWQxKzAp
# BgNVBAMTIlNlY3RpZ28gUHVibGljIENvZGUgU2lnbmluZyBDQSBSMzYwggGiMA0G
# CSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQCbK51T+jU/jmAGQ2rAz/V/9shTUxjI
# ztNsfvxYB5UXeWUzCxEeAEZGbEN4QMgCsJLZUKhWThj/yPqy0iSZhXkZ6Pg2A2NV
# DgFigOMYzB2OKhdqfWGVoYW3haT29PSTahYkwmMv0b/83nbeECbiMXhSOtbam+/3
# 6F09fy1tsB8je/RV0mIk8XL/tfCK6cPuYHE215wzrK0h1SWHTxPbPuYkRdkP05Zw
# mRmTnAO5/arnY83jeNzhP06ShdnRqtZlV59+8yv+KIhE5ILMqgOZYAENHNX9SJDm
# +qxp4VqpB3MV/h53yl41aHU5pledi9lCBbH9JeIkNFICiVHNkRmq4TpxtwfvjsUe
# dyz8rNyfQJy/aOs5b4s+ac7IH60B+Ja7TVM+EKv1WuTGwcLmoU3FpOFMbmPj8pz4
# 4MPZ1f9+YEQIQty/NQd/2yGgW+ufflcZ/ZE9o1M7a5Jnqf2i2/uMSWymR8r2oQBM
# dlyh2n5HirY4jKnFH/9gRvd+QOfdRrJZb1sCAwEAAaOCAWQwggFgMB8GA1UdIwQY
# MBaAFDLrkpr/NZZILyhAQnAgNpFcF4XmMB0GA1UdDgQWBBQPKssghyi47G9IritU
# pimqF6TNDDAOBgNVHQ8BAf8EBAMCAYYwEgYDVR0TAQH/BAgwBgEB/wIBADATBgNV
# HSUEDDAKBggrBgEFBQcDAzAbBgNVHSAEFDASMAYGBFUdIAAwCAYGZ4EMAQQBMEsG
# A1UdHwREMEIwQKA+oDyGOmh0dHA6Ly9jcmwuc2VjdGlnby5jb20vU2VjdGlnb1B1
# YmxpY0NvZGVTaWduaW5nUm9vdFI0Ni5jcmwwewYIKwYBBQUHAQEEbzBtMEYGCCsG
# AQUFBzAChjpodHRwOi8vY3J0LnNlY3RpZ28uY29tL1NlY3RpZ29QdWJsaWNDb2Rl
# U2lnbmluZ1Jvb3RSNDYucDdjMCMGCCsGAQUFBzABhhdodHRwOi8vb2NzcC5zZWN0
# aWdvLmNvbTANBgkqhkiG9w0BAQwFAAOCAgEABv+C4XdjNm57oRUgmxP/BP6YdURh
# w1aVcdGRP4Wh60BAscjW4HL9hcpkOTz5jUug2oeunbYAowbFC2AKK+cMcXIBD0Zd
# OaWTsyNyBBsMLHqafvIhrCymlaS98+QpoBCyKppP0OcxYEdU0hpsaqBBIZOtBajj
# cw5+w/KeFvPYfLF/ldYpmlG+vd0xqlqd099iChnyIMvY5HexjO2AmtsbpVn0OhNc
# WbWDRF/3sBp6fWXhz7DcML4iTAWS+MVXeNLj1lJziVKEoroGs9Mlizg0bUMbOalO
# hOfCipnx8CaLZeVme5yELg09Jlo8BMe80jO37PU8ejfkP9/uPak7VLwELKxAMcJs
# zkyeiaerlphwoKx1uHRzNyE6bxuSKcutisqmKL5OTunAvtONEoteSiabkPVSZ2z7
# 6mKnzAfZxCl/3dq3dUNw4rg3sTCggkHSRqTqlLMS7gjrhTqBmzu1L90Y1KWN/Y5J
# KdGvspbOrTfOXyXvmPL6E52z1NZJ6ctuMFBQZH3pwWvqURR8AgQdULUvrxjUYbHH
# j95Ejza63zdrEcxWLDX6xWls/GDnVNueKjWUH3fTv1Y8Wdho698YADR7TNx8X8z2
# Bev6SivBBOHY+uqiirZtg0y9ShQoPzmCcn63Syatatvx157YK9hlcPmVoa1oDE5/
# L9Uo2bC5a4CH2RwwggZIMIIEsKADAgECAhEA5SHpfAJbIErG15QH7BB+KDANBgkq
# hkiG9w0BAQwFADBUMQswCQYDVQQGEwJHQjEYMBYGA1UEChMPU2VjdGlnbyBMaW1p
# dGVkMSswKQYDVQQDEyJTZWN0aWdvIFB1YmxpYyBDb2RlIFNpZ25pbmcgQ0EgUjM2
# MB4XDTI2MDUxOTAwMDAwMFoXDTI3MDUxOTIzNTk1OVowXjELMAkGA1UEBhMCVVMx
# EzARBgNVBAgMCkNhbGlmb3JuaWExHDAaBgNVBAoME1ZpdGtvIFNvZnR3YXJlLCBM
# TEMxHDAaBgNVBAMME1ZpdGtvIFNvZnR3YXJlLCBMTEMwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQDWKBYoiUr8LiKKwN5XL3M5Kj76CNnsggqUVMHBtNUu
# qu8g3mGYst5OOsA2zpMeX6nt3JtyMTUVO5uNX7ljTNw6G8AK3/FaWv8nN5MYIQn5
# 8VqrbHM1okfJohJ12JyaHR3Czcq/ukpiLd1AIuA4ACPzNgpS5Ac6r1rlQnbWfqsj
# e3zMRa1T8lpocwEdZkTjve2S7ihqil81ALryz/+A6cXXP2fVMetbVnJmEENmm+E0
# fdZQptp6VTVxGeK/pCI6ozbKH3NaH9fZAcvtD8heCMkLS/tgCl5vsAKoZ9JcbfV6
# Kjzz7H1KVMuqyhRs6+6dkGNKaxmTiasQFIMJH4TkUMdhcyun57LWSQ2xViXrmCe0
# d68C5vzdKbpU42btTw7o4mKEAGkKRQNjnEErORPAcPKekeyn5vKk9EtxdF3f+th3
# Rt1and8Z+1tW7p3U5HvgksJR1StxSem3FeWYYv//REvChMOdgpMqk7bCtbT/2DBl
# 1maX7SgblwQHVyXDfkz41enLAc6jEwc8BLhtQh4Kzs2rV5f3P2PjPmOgc2pVVa4R
# zk6UbF819dYND7i8HYISbXIAvLN8c+kYaxxTTCPCRN/w2VdWeKZVAMv5jNsyUgpP
# Y4t7EyQQ8kcp1mO/3mSdLJFsJvWDnyBjTuEBGGwW8sR2AlzjlvLnmTgB4IiNFRVI
# TwIDAQABo4IBiTCCAYUwHwYDVR0jBBgwFoAUDyrLIIcouOxvSK4rVKYpqhekzQww
# HQYDVR0OBBYEFHn6Qx0kNzcRnUxN9st73DlJY0GUMA4GA1UdDwEB/wQEAwIHgDAM
# BgNVHRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMEoGA1UdIARDMEEwNQYM
# KwYBBAGyMQECAQMCMCUwIwYIKwYBBQUHAgEWF2h0dHBzOi8vc2VjdGlnby5jb20v
# Q1BTMAgGBmeBDAEEATBJBgNVHR8EQjBAMD6gPKA6hjhodHRwOi8vY3JsLnNlY3Rp
# Z28uY29tL1NlY3RpZ29QdWJsaWNDb2RlU2lnbmluZ0NBUjM2LmNybDB5BggrBgEF
# BQcBAQRtMGswRAYIKwYBBQUHMAKGOGh0dHA6Ly9jcnQuc2VjdGlnby5jb20vU2Vj
# dGlnb1B1YmxpY0NvZGVTaWduaW5nQ0FSMzYuY3J0MCMGCCsGAQUFBzABhhdodHRw
# Oi8vb2NzcC5zZWN0aWdvLmNvbTANBgkqhkiG9w0BAQwFAAOCAYEAUVdCTQkRJxrW
# BRSrtrKvOaGKpq695JnmMjwQbV8VdXOKAsUb1MVIshMxEozaaRVhhA3F4feMx0fk
# ZBjyxE6iMG5j5uwhu1OfL2wr4yQCGe/0X1MD8hliYyMghpkHDNB8HyHCFfO3FJr+
# kJBxx5tObAXvAwuLNdsnNtQWhmTR9zDlPjiv+RV/jqH6J2be0IRJnckt8ryAMZ+x
# 7eSNjjgeBnPFFHGqVN3z6d0Xe9sNdC7upO7i0Zl6x1nGl6QHni5YkxfYUVssekKD
# 3UuWiVVk+6Vo0TuWqrWSMZjjLmgvnRbdrZKZQuZOi44XWrjD6IE7hQZhkNa9g0jg
# sWPJs/3c0r05IDwPpcKeULviHqspYW5Kdoth7GUfkLzYk6qoHg6iUVhPIcpat6KX
# JxTxzzdbepbPjp2b8bVvC1sgz4vf3BhlHNVqC+D1EvxY+ffLozt3hhnYxBRnuuRk
# /bSwfEi2kxDAWX4FZ+Kd8gzU6Aq94dH+j4YvkS7IeRvyE19ML16mMIIGgjCCBGqg
# AwIBAgIQNsKwvXwbOuejs902y8l1aDANBgkqhkiG9w0BAQwFADCBiDELMAkGA1UE
# BhMCVVMxEzARBgNVBAgTCk5ldyBKZXJzZXkxFDASBgNVBAcTC0plcnNleSBDaXR5
# MR4wHAYDVQQKExVUaGUgVVNFUlRSVVNUIE5ldHdvcmsxLjAsBgNVBAMTJVVTRVJU
# cnVzdCBSU0EgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwHhcNMjEwMzIyMDAwMDAw
# WhcNMzgwMTE4MjM1OTU5WjBXMQswCQYDVQQGEwJHQjEYMBYGA1UEChMPU2VjdGln
# byBMaW1pdGVkMS4wLAYDVQQDEyVTZWN0aWdvIFB1YmxpYyBUaW1lIFN0YW1waW5n
# IFJvb3QgUjQ2MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAiJ3YuUVn
# nR3d6LkmgZpUVMB8SQWbzFoVD9mUEES0QUCBdxSZqdTkdizICFNeINCSJS+lV1ip
# nW5ihkQyC0cRLWXUJzodqpnMRs46npiJPHrfLBOifjfhpdXJ2aHHsPHggGsCi7uE
# 0awqKggE/LkYw3sqaBia67h/3awoqNvGqiFRJ+OTWYmUCO2GAXsePHi+/JUNAax3
# kpqstbl3vcTdOGhtKShvZIvjwulRH87rbukNyHGWX5tNK/WABKf+Gnoi4cmisS7o
# SimgHUI0Wn/4elNd40BFdSZ1EwpuddZ+Wr7+Dfo0lcHflm/FDDrOJ3rWqauUP8hs
# okDoI7D/yUVI9DAE/WK3Jl3C4LKwIpn1mNzMyptRwsXKrop06m7NUNHdlTDEMovX
# AIDGAvYynPt5lutv8lZeI5w3MOlCybAZDpK3Dy1MKo+6aEtE9vtiTMzz/o2dYfdP
# 0KWZwZIXbYsTIlg1YIetCpi5s14qiXOpRsKqFKqav9R1R5vj3NgevsAsvxsAnI8O
# a5s2oy25qhsoBIGo/zi6GpxFj+mOdh35Xn91y72J4RGOJEoqzEIbW3q0b2iPuWLA
# 911cRxgY5SJYubvjay3nSMbBPPFsyl6mY4/WYucmyS9lo3l7jk27MAe145GWxK4O
# 3m3gEFEIkv7kRmefDR7Oe2T1HxAnICQvr9sCAwEAAaOCARYwggESMB8GA1UdIwQY
# MBaAFFN5v1qqK0rPVIDh2JvAnfKyA2bLMB0GA1UdDgQWBBT2d2rdP/0BE/8WoWyC
# Ai/QCj0UJTAOBgNVHQ8BAf8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zATBgNVHSUE
# DDAKBggrBgEFBQcDCDARBgNVHSAECjAIMAYGBFUdIAAwUAYDVR0fBEkwRzBFoEOg
# QYY/aHR0cDovL2NybC51c2VydHJ1c3QuY29tL1VTRVJUcnVzdFJTQUNlcnRpZmlj
# YXRpb25BdXRob3JpdHkuY3JsMDUGCCsGAQUFBwEBBCkwJzAlBggrBgEFBQcwAYYZ
# aHR0cDovL29jc3AudXNlcnRydXN0LmNvbTANBgkqhkiG9w0BAQwFAAOCAgEADr5l
# Qe1oRLjlocXUEYfktzsljOt+2sgXke3Y8UPEooU5y39rAARaAdAxUeiX1ktLJ3+l
# gxtoLQhn5cFb3GF2SSZRX8ptQ6IvuD3wz/LNHKpQ5nX8hjsDLRhsyeIiJsms9yAW
# nvdYOdEMq1W61KE9JlBkB20XBee6JaXx4UBErc+YuoSb1SxVf7nkNtUjPfcxuFtr
# QdRMRi/fInV/AobE8Gw/8yBMQKKaHt5eia8ybT8Y/Ffa6HAJyz9gvEOcF1VWXG8O
# MeM7Vy7Bs6mSIkYeYtddU1ux1dQLbEGur18ut97wgGwDiGinCwKPyFO7ApcmVJOt
# lw9FVJxw/mL1TbyBns4zOgkaXFnnfzg4qbSvnrwyj1NiurMp4pmAWjR+Pb/SIduP
# nmFzbSN/G8reZCL4fvGlvPFk4Uab/JVCSmj59+/mB2Gn6G/UYOy8k60mKcmaAZsE
# VkhOFuoj4we8CYyaR9vd9PGZKSinaZIkvVjbH/3nlLb0a7SBIkiRzfPfS9T+Jesy
# lbHa1LtRV9U/7m0q7Ma2CQ/t392ioOssXW7oKLdOmMBl14suVFBmbzrt5V5cQPnw
# td3UOTpS9oCG+ZZheiIvPgkDmA8FzPsnfXW5qHELB43ET7HHFHeRPRYrMBKjkb8/
# IN7Po0d0hQoF4TeMM+zYAJzoKQnVKOLg8pZVPT8wgganMIIEj6ADAgECAhEAkKwI
# ciD9xafEa1zHDfc9BjANBgkqhkiG9w0BAQwFADBXMQswCQYDVQQGEwJHQjEYMBYG
# A1UEChMPU2VjdGlnbyBMaW1pdGVkMS4wLAYDVQQDEyVTZWN0aWdvIFB1YmxpYyBU
# aW1lIFN0YW1waW5nIFJvb3QgUjQ2MB4XDTI2MDMyNTAwMDAwMFoXDTQxMDMyNDIz
# NTk1OVowVTELMAkGA1UEBhMCR0IxGDAWBgNVBAoTD1NlY3RpZ28gTGltaXRlZDEs
# MCoGA1UEAxMjU2VjdGlnbyBQdWJsaWMgVGltZSBTdGFtcGluZyBDQSBSNDEwggIi
# MA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCu5EqiAa2CHGL5Zi1bmgPM8NUX
# wYZJ+BtQqHps43GLTC+sjVLypsBh+8uv+TLkgtVGD//vSmA0qrzELf9YRCh2MTAA
# /aGaQZKGg0BRCmziR3pbCnvgWjtGXBDUyn3j3K2lZAO8KxgFtlxwOYEAkL+CCqK4
# v9zzTl8ZwzDpPMiDIFa5THk8an1ieF5I09cXNrPQw+1ER1liThaG0z6FrOpqwxZW
# mPRZQBw2E32878UB1bL0Zp91vuWZgsMpNNiPCoBj0/1F+LE8+NRokfqacFI0F2tf
# trRB2W7HQClLR9zjxFbWb5be2rceIfNyHUUfKGIvMI2NzoxSlxXnFqUG887D8W1C
# j8DFok688JKxWvHR/9aQykSbd+9Vutj36ij2sgq/125wTpUZ/AgC0ph50bRs7gFr
# UyaXE9wSsOqMvCCC+sEm7vd/BemSG0TSHNXSmyCba+FCzekeWX03TRIcF3Laqd0R
# w24OH7jpei4zaGhcI7nfdhBA4c8RScxNY6jeHLHHmSMMTk9Wqn7H4dLhUBP5YEwb
# gbN4uv1i9ltTnHli8t1xHV0StX9BFgrnmunTX19kUXY1H5ORJbRZyZDdvm1oZyte
# Dj0SnMozr+YSmdIleDUTXdfoY7b2taz8s2+QbOxLxcahEIYGWzqu6h955tKwcANH
# cZ4gTmAhT3btuOiQsQIDAQABo4IBbjCCAWowHwYDVR0jBBgwFoAU9ndq3T/9ARP/
# FqFsggIv0Ao9FCUwHQYDVR0OBBYEFDp0pQxnxkJQwv21/Me7KTSC9Hq5MA4GA1Ud
# DwEB/wQEAwIBhjASBgNVHRMBAf8ECDAGAQH/AgEAMBMGA1UdJQQMMAoGCCsGAQUF
# BwMIMCMGA1UdIAQcMBowCAYGZ4EMAQQCMA4GDCsGAQQBsjEBAgEDCDBMBgNVHR8E
# RTBDMEGgP6A9hjtodHRwOi8vY3JsLnNlY3RpZ28uY29tL1NlY3RpZ29QdWJsaWNU
# aW1lU3RhbXBpbmdSb290UjQ2LmNybDB8BggrBgEFBQcBAQRwMG4wRwYIKwYBBQUH
# MAKGO2h0dHA6Ly9jcnQuc2VjdGlnby5jb20vU2VjdGlnb1B1YmxpY1RpbWVTdGFt
# cGluZ1Jvb3RSNDYucDdjMCMGCCsGAQUFBzABhhdodHRwOi8vb2NzcC5zZWN0aWdv
# LmNvbTANBgkqhkiG9w0BAQwFAAOCAgEAMt5SR2bxngNm+N8oc6Gq76Gx1c235fkX
# 7jw8Ho9MAkJGADerHE7dhsBXttqmzgr/7ZZahZSykGRPhPY1crj028kB8KzO0dKC
# 2qQBAwtfgqMLKkkX/6bYq2uT33eD6ByAp2/XKD0LcmZh0kKecvSBr6ln9ajX6u1d
# nx2fA7xEKy1M3qBhfQSUWLtjs2nFt0ELVLptzTlX9ID0cL+iOPfdboZ3CelT+JXK
# VKR2Sge0d4YiFAtPZkfSo8z1Z1x7y/Z9mwMIlBAnyuWXs4YsNuxdrYIt/QxE31PD
# OJ9DesS4Bc7H9OTORlEV/AvfiF/VepKZpira1MzLYuCw+uoLZn/pkpvd+CvNTS+m
# EHjBJNa6WK1j8qXFu+jIq+sG9QILHiyB6p/xpHrkJu8zkw393+VqF9eKlTY2VjRx
# dycZLrVemZ4Yp3wi33b+W58CllH3HqjmowlZ7SOrgmx8YwYOkgrHsXOQHyBp6O4F
# Rb8In0+FzjT7ElGie9V7CfhL3IlVFZ4zjuKsZtH1iU3fGu4z/JnOGT6sCb0BbTqe
# /uhvpFCQBdH5xPGIA/LrbQUXjU2tWJgHhTIqnN/HvHyOHi5tM4zP3nhgh2rJ6Kqq
# 2xsHBeNYs/R18xQ8DeIg+c90Eoaeh0YlN1KU8AyYol3K9M+qY5ez8syd/7ZlrRno
# VewgH3P1pcswggbiMIIEyqADAgECAhEA507yVbBQT/rbpt/3/IujFTANBgkqhkiG
# 9w0BAQwFADBVMQswCQYDVQQGEwJHQjEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVk
# MSwwKgYDVQQDEyNTZWN0aWdvIFB1YmxpYyBUaW1lIFN0YW1waW5nIENBIFI0MTAe
# Fw0yNjAzMjUwMDAwMDBaFw0zNzA2MjQyMzU5NTlaMHIxCzAJBgNVBAYTAkdCMRcw
# FQYDVQQIEw5HcmVhdGVyIExvbmRvbjEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVk
# MTAwLgYDVQQDEydTZWN0aWdvIFB1YmxpYyBUaW1lIFN0YW1waW5nIFNpZ25lciBS
# MzcwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCy/8NtS9xQ2UUtBRF3
# 2bj7VK3n4m50Uqjk/zTciSziYV40H1LKah0/oEklYG42E4VCP3DvsBUB6DmpCkDZ
# 0jCnZBPIEevaH15ZJOQwFWP2ZXr5YjlJpb68Nlbs+ElNvKx32/1YHde3qqUSLybj
# ulxPLz6T85+HOIqK7M1Bep8LspyhEP/q6nw5kGxTSrGvufmeH+JF8CnVBcVMFA40
# FlIYh0cDJVFhhfTfdWgLy/vWuLMQoKkf3s/FvByf16r0rtbyHm/iemwxSioJL9zy
# ZDDKUNAbHXl0dhXo2VxUV2NcPXWXuoKsjL+6cfk6Vm2DHnxAlFdFsaBDIF1JOkSn
# C6PeLlBznZn2buF3vIIYJcq6N/zeFRCk4/HXDz7zgRsRRMdUB+rhyk5FoZaBjw0n
# Lq3GZ3fClLUx5es5pUAxzNODMBn7JkFYip2BAGBPER5eV0ROhk6tGTG+fUiMiV+v
# gjg1YnP5FvnYWyEtWeQD/B2hp3vz0RvtdkM0p3igyadzrfpOBq5ppVk/YsuhTQkP
# 99ivneHAGfi5e7lmxJ+meoBPrRLuzMmb81rzzbESjJHMsn5RVtc6Ucs7rcMqQC13
# PUIO7BbGBETV2ufCmV6lPTp3P7XJOvmnUCRTPbVvMTpxP/z+SOHg4/OCBhiqs4FA
# 9+4oQvlkk9w32NGASli9GWrm5wIDAQABo4IBjjCCAYowHwYDVR0jBBgwFoAUOnSl
# DGfGQlDC/bX8x7spNIL0erkwHQYDVR0OBBYEFGEQ6XoSr1HEhdTyz6R0D1DNIK/4
# MA4GA1UdDwEB/wQEAwIGwDAMBgNVHRMBAf8EAjAAMBYGA1UdJQEB/wQMMAoGCCsG
# AQUFBwMIMEoGA1UdIARDMEEwCAYGZ4EMAQQCMDUGDCsGAQQBsjEBAgEDCDAlMCMG
# CCsGAQUFBwIBFhdodHRwczovL3NlY3RpZ28uY29tL0NQUzBKBgNVHR8EQzBBMD+g
# PaA7hjlodHRwOi8vY3JsLnNlY3RpZ28uY29tL1NlY3RpZ29QdWJsaWNUaW1lU3Rh
# bXBpbmdDQVI0MS5jcmwwegYIKwYBBQUHAQEEbjBsMEUGCCsGAQUFBzAChjlodHRw
# Oi8vY3J0LnNlY3RpZ28uY29tL1NlY3RpZ29QdWJsaWNUaW1lU3RhbXBpbmdDQVI0
# MS5jcnQwIwYIKwYBBQUHMAGGF2h0dHA6Ly9vY3NwLnNlY3RpZ28uY29tMA0GCSqG
# SIb3DQEBDAUAA4ICAQAD6j2N0azN+hl6k6bKB5/U6VuSOs93ZBb3Pczy9VtBIKu4
# 947Z5GwL0aFngIxl+GSuLFrJgPruBCRvKJEJsm7kv+LQ1COVCEG9tZ+IRtr4ocUo
# a53lgdFaENlS0N4wgkZkbQEPv+x+1lSjYh+T4JeL9mUznT7Erc6Sp5dWLka5sMP/
# m3GZi6oJPdPcsCKWagH7m2H2xDGIyHJC5PdH9phvi/KmhkktiSVTNNqVeV5bWdX2
# zhRE6UTfz0IcMoCL996lFIydXxOCE4MNDHDM0as4lnTiT/KHMccO6l8c9TnUVgmp
# ci9ar1IABZ2U1XUkYjGGSn9MC3EHDP9V39VuBVvZ33/BEV/EWSRrf07T7jFplKX+
# gQr/UOqPGMlE7ZJ72UaUkNJy7bVl3bcLKzdpjIHzLkf/4MVa1V7w8wqCv5W4gOnR
# GTlud5UMARbRM8BPxR/CXYXoMmIOD8pmTk2axgRL4LG8XtuchISdCHRmtacAmLGq
# 5XSYSVTHTXADlO48iDKh3HM2r98LSF6f0sG12d8V9Jn7C3wDUieOxuKj4MdWrW+h
# iJU2kF87v6eH00HgCFFc2V0+CvfOCMn7juzS41jLaINcBlKWQ/fKb/uDLfWOW73z
# 1I2lFY7Xj8tQ1XYtK5eREjWItM8jpl1cbQOc88btR+0XS2TmboE/141+va2PWzGC
# BkIwggY+AgEBMGkwVDELMAkGA1UEBhMCR0IxGDAWBgNVBAoTD1NlY3RpZ28gTGlt
# aXRlZDErMCkGA1UEAxMiU2VjdGlnbyBQdWJsaWMgQ29kZSBTaWduaW5nIENBIFIz
# NgIRAOUh6XwCWyBKxteUB+wQfigwDQYJYIZIAWUDBAIBBQCggYQwGAYKKwYBBAGC
# NwIBDDEKMAigAoAAoQKAADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgor
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgu68kkZ/s
# INd/6bHuQrfOqtqbMsqPS/97EjLmQrWT4HQwDQYJKoZIhvcNAQEBBQAEggIAQgoC
# 8bAWOjMWyoGIhGePlRUiKWFCoIBLSEYxTOK1b4DpKM0c06233EWMLZFJSz6J6o/f
# Oq/4yrWfmZ9aCV5soqSxsnu1gNU+C1RtxzN9ImYmWlzvY7mfSgNx3bWGcgm1TF0j
# yyq36QY0flUY46KiKveqkU314idJFWCy0q76TVcqnzl53/1rzPrBMq5997OJKQrg
# RFacS7gUkX0BLrnIvna3ceo8Ou+esNeF5JjhN13NtufjhsMVG7ikHNuZ2J+ZZ52f
# Cl4hgVJ1N2xje8X9ZtXI8EnglsJInMeLdwzRPoBN/BbeNN8P4yqTsI+PaKBeCd70
# JXOGWHuGqEuB7oqXe1oNLXWpqHg/cAA3nRpAUmcYUdJ6+phm9W85XUMxKNpuhyaP
# j7Mc22U/ab152Un3P7eMOZPnfSxfE94J2hW34w4mvOE1x/tEM8svbdMVEYySjNwm
# abkgRayJxw5s2KmA78QWuFqWSO1gfjzTEwgZxCf+pqeGCm5V5Q7KKSPFqemLTEvP
# 1oUgv/AvXViS/fhG6oosxJ6PhQulDJ8D35nbPiK86m8G/i2ftnmzMSLrLadpKuQv
# dacrfn3RcPa2eG6snM4rs7j5C/VGNR0RA3zuRLPOZf9Oq2TOpqQxMiukH3418Pxd
# nMr0+O65BiHY2qaz9hcSL++vz7DbNDnTxskH2YuhggMjMIIDHwYJKoZIhvcNAQkG
# MYIDEDCCAwwCAQEwajBVMQswCQYDVQQGEwJHQjEYMBYGA1UEChMPU2VjdGlnbyBM
# aW1pdGVkMSwwKgYDVQQDEyNTZWN0aWdvIFB1YmxpYyBUaW1lIFN0YW1waW5nIENB
# IFI0MQIRAOdO8lWwUE/626bf9/yLoxUwDQYJYIZIAWUDBAICBQCgeTAYBgkqhkiG
# 9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0yNjA5MjAwMjU0NTRa
# MD8GCSqGSIb3DQEJBDEyBDANkwitHcc0ReVFL3tRpBNHFwoLbe0pViOgTWa/J6qH
# +atK6x/vzI4D8nlvA1gIkkEwDQYJKoZIhvcNAQEBBQAEggIAGnALQPs56aZxlRk+
# DJEwxTGaEK0UczI7NgQRa6YjaNoDcEECQRgpzFUNnNzHvKdM+/Fl79Bz2+bJ9p83
# BoADI1Xf38AzAT6WHVU2SKytItbtJjJdm33Xjf3WgY/RPbipzGbUQW0KVSWTa8ES
# 27qsio0XI9goz3OW3Cz/hMWN6UqLkJJU1b71GLdvgAU5VTuaSSl5uECSJolFEUpe
# bcIpyUIY5iayBtZqv0VuV/lb7Ccz2MQH32mWYNN9Qsf44lAFpKZR545P1FeHv1qn
# rh3T6VfQXr/WNqNr45nCgqnJjbRMbAFAc1ZIJT9nMN75SoeOfQyTNQ5Fka+nuuNv
# TW51jHF46S4tjCJ3rPkUCRQPfHsc/wzFxNLe7h+M9GEmGPUqjfi9GR9bWoWI4NfZ
# DSvaQSiw7zkWDpH+XlCsbCqrQtp10OMgjjS4+yyi6GNOufhFVk43oMtA5873PnBF
# vhsbubdFsucmzBxQW+O1BQCn3dMkuvzHCmsB0eNYjIG/sSs6UKGSlzN8gC8l+xXK
# yX///8dABgErZapA9M/3tmznIh6h1YPCg9E8wPjNtjFu1Ilf0pKLQkZsZnYFDtc6
# dQWaiRjgeDLuedH3PDG9PWX3CLYtaY4czYWk/sR9eVezRKDfxX89LOv7aQLJ+y5p
# aFnTgW4PCrlwY/vwBICsyOe1JB8=
# SIG # End signature block

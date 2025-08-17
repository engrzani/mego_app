#Requires -Version 5.1
<#
.SYNOPSIS
  Hoofdmenu (Run ALL + resume). ASCII, PS 5.1.
#>

$ErrorActionPreference = 'Stop'

# Paden
$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$ModuleRoot = Join-Path $ScriptRoot 'modules'
$LogFile    = Join-Path $ScriptRoot 'logs\InstallatieLogMJ.txt'
$StateFile  = Join-Path $ScriptRoot 'settings\_runall.state'

# Schone module-reload
Remove-Module loggingMJ -Force -ErrorAction SilentlyContinue
Remove-Item Function:\Write-Log -Force -ErrorAction SilentlyContinue
Remove-Item Function:\Write-LogMJ -Force -ErrorAction SilentlyContinue
Import-Module (Join-Path $ModuleRoot 'loggingMJ.psm1') -Force
Set-LogPath -Path $LogFile

Remove-Module algemeenMJ, domainsettingsMJ -Force -ErrorAction SilentlyContinue
Import-Module (Join-Path $ModuleRoot 'algemeenMJ.psm1') -Force
Import-Module (Join-Path $ModuleRoot 'domainsettingsMJ.psm1') -Force

function Pause-Menu { Read-Host "Druk op Enter om verder te gaan..." | Out-Null }

function Test-AutoLogonConfigured {
    $wl = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    try {
        $val = Get-ItemProperty -Path $wl -Name 'AutoAdminLogon','DefaultUserName','DefaultPassword' -ErrorAction Stop
        return ($val.AutoAdminLogon -eq '1' -and $val.DefaultUserName -and $val.DefaultPassword)
    } catch { return $false }
}

function Ensure-AutoLogon {
    if (-not (Test-AutoLogonConfigured)) {
        Write-Host ""
        Write-Host "Autologon is nog niet ingesteld. (Alleen voor labo/examen - plaintext in registry)" -ForegroundColor Yellow
        $pwSecure = Read-Host "Geef Administrator-wachtwoord (plaintext vereist door opdracht)" -AsSecureString
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($pwSecure)
        $pw   = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
        try {
            Set-AutoLogon -User 'Administrator' -Password $pw -Domain $env:COMPUTERNAME
            Write-LogMJ "AutoLogon ingesteld via menu."
        } catch {
            Write-LogMJ "FOUT bij instellen AutoLogon via menu: $($_.Exception.Message)"
            throw
        } finally {
            if ($bstr -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
        }
    } else {
        Write-LogMJ "AutoLogon reeds geconfigureerd."
    }
}

function Show-Menu {
    Clear-Host
    Write-Host "======== Scripting Project Menu ========" -ForegroundColor Cyan
    Write-Host " 1) Basisconfiguratie - Server (hostname + netwerk)"
    Write-Host " 2) Domain Controller installeren/promoten"
    Write-Host " 3) Organizational Units aanmaken"
    Write-Host " 4) Security Groups aanmaken"
    Write-Host " 5) Domeingebruikers aanmaken"
    Write-Host " 6) Users -> Security Groups toevoegen"
    Write-Host " 7) Mappenstructuur aanmaken (mappen.txt)"
    Write-Host " 8) SMB-shares aanmaken (shares.csv)"
    Write-Host " 9) NTFS + Share permissies toepassen (rechten.csv)"
    Write-Host " A) RUN ALL (1 -> 9) met resume"
    Write-Host " L) Toon logbestand"
    Write-Host " 0) Exit"
    Write-Host "----------------------------------------"
}

function Invoke-Step {
    param([Parameter(Mandatory)][string]$Id)
    switch ($Id.ToUpper()) {
        '1' { Write-LogMJ "Stap 1 start: Basisconfiguratie.";           try { Set-Basisinstellingen }    catch { Write-LogMJ "FOUT stap 1: $($_.Exception.Message)" } ; Write-LogMJ "Stap 1 klaar." }
        '2' { Write-LogMJ "Stap 2 start: Domain Controller promotie.";    try { Install-DomainController }  catch { Write-LogMJ "FOUT stap 2: $($_.Exception.Message)" } ; Write-LogMJ "Stap 2 klaar (mogelijke reboot)." }
        '3' { Write-LogMJ "Stap 3 start: OU's.";                          try { New-OrganizationalUnits }   catch { Write-LogMJ "FOUT stap 3: $($_.Exception.Message)" } ; Write-LogMJ "Stap 3 klaar." }
        '4' { Write-LogMJ "Stap 4 start: Security Groups.";               try { New-SecurityGroups }        catch { Write-LogMJ "FOUT stap 4: $($_.Exception.Message)" } ; Write-LogMJ "Stap 4 klaar." }
        '5' { Write-LogMJ "Stap 5 start: Users.";                         try { New-DomainUsers }           catch { Write-LogMJ "FOUT stap 5: $($_.Exception.Message)" } ; Write-LogMJ "Stap 5 klaar." }
        '6' { Write-LogMJ "Stap 6 start: Users -> Groups.";               try { Add-UsersToSecurityGroups } catch { Write-LogMJ "FOUT stap 6: $($_.Exception.Message)" } ; Write-LogMJ "Stap 6 klaar." }
        '7' { Write-LogMJ "Stap 7 start: Mappenstructuur.";               try { New-FolderStructure }       catch { Write-LogMJ "FOUT stap 7: $($_.Exception.Message)" } ; Write-LogMJ "Stap 7 klaar." }
        '8' { Write-LogMJ "Stap 8 start: Shares.";                        try { New-NetworkShares }         catch { Write-LogMJ "FOUT stap 8: $($_.Exception.Message)" } ; Write-LogMJ "Stap 8 klaar." }
        '9' { Write-LogMJ "Stap 9 start: NTFS + Share permissions.";      try { Set-NTFSPermissions }       catch { Write-LogMJ "FOUT stap 9: $($_.Exception.Message)" } ; Write-LogMJ "Stap 9 klaar." }
        default { Write-Host "Onbekende stap: $Id" -ForegroundColor Red }
    }
}

function Get-ResumeState { if (Test-Path $StateFile) { (Get-Content $StateFile -ErrorAction SilentlyContinue).Trim() } else { '' } }
function Set-ResumeState {
    param([string]$Value)
    $dir = Split-Path $StateFile -Parent
    if (-not (Test-Path $dir)) { New-Item -Path $dir -ItemType Directory -Force | Out-Null }
    if ([string]::IsNullOrWhiteSpace($Value)) {
        if (Test-Path $StateFile) { Remove-Item $StateFile -Force -ErrorAction SilentlyContinue }
    } else {
        Set-Content -Path $StateFile -Value $Value -Encoding UTF8
    }
}

function Run-All {
    $order = @('1','2','3','4','5','6','7','8','9')
    $current = Get-ResumeState
    if (-not $current) {
        Ensure-AutoLogon
        $current = '1'
        Set-ResumeState -Value $current
        Write-LogMJ "RUN ALL gestart."
    } else {
        Write-LogMJ ("RUN ALL hervat vanaf stap {0}" -f $current)
    }
    $startIndex = $order.IndexOf($current); if ($startIndex -lt 0) { $startIndex = 0 }
    for ($i = $startIndex; $i -lt $order.Count; $i++) {
        $step = $order[$i]
        Invoke-Step -Id $step
        if ($i -lt $order.Count - 1) { Set-ResumeState -Value $order[$i+1] } else { Set-ResumeState -Value '' }
    }
    Write-LogMJ "RUN ALL voltooid."
    Write-Host "Alle stappen uitgevoerd. Log: $LogFile" -ForegroundColor Green
}

function Show-Log {
    if (Test-Path $LogFile) {
        Write-Host ""
        Write-Host "--- Laatste 80 regels van het log ---" -ForegroundColor DarkCyan
        Get-Content -Path $LogFile -Tail 80 | ForEach-Object { Write-Host $_ }
        Write-Host ""
        Write-Host "(Volledig logpad: $LogFile)"
    } else {
        Write-Host "Nog geen log gevonden op: $LogFile" -ForegroundColor Yellow
    }
}

# Start
Ensure-AutoLogon

$existingState = Get-ResumeState
if ($existingState) {
    Write-LogMJ ("Menu gestart met bestaande RUN ALL state: volgende stap {0}" -f $existingState)
    Run-All
}

:MainMenu while ($true) {
    Show-Menu
    $choice = Read-Host "Keuze"
    switch ($choice.ToUpper()) {
        '0' { Write-LogMJ "Exit gekozen via menu."; break MainMenu }
        'L' { Show-Log; Pause-Menu }
        'A' { Run-All;   Pause-Menu }
        { $_ -match '^[1-9]$' } { Invoke-Step -Id $_; Pause-Menu }
        default { Write-Host "Ongeldige keuze." -ForegroundColor Red; Start-Sleep -Seconds 1 }
    }
}

# modules\loggingMJ.psm1  (PS 5.1 safe, ASCII-only)
$script:LogPath = $null

function Set-LogPath {
    param([Parameter(Mandatory)][string]$Path)
    $dir = Split-Path -Parent $Path
    if (-not (Test-Path $dir)) { New-Item -Path $dir -ItemType Directory -Force | Out-Null }
    $script:LogPath = $Path
    if (-not (Test-Path $script:LogPath)) { New-Item -Path $script:LogPath -ItemType File -Force | Out-Null }
}

function Write-LogMJ {
    param(
        [Parameter(Mandatory,Position=0)][string]$Message,
        [ValidateSet('Info','Warn','Error')][string]$Level = 'Info'
    )
    if (-not $script:LogPath) {
        $root = Split-Path $PSScriptRoot -Parent
        Set-LogPath -Path (Join-Path $root 'logs\InstallatieLogMJ.txt')
    }
    $prefix = if ($Level -eq 'Info') { '[Info] ' } elseif ($Level -eq 'Warn') { '[Warn] ' } else { '[Error] ' }
    $line = ('{0} - {1}{2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $prefix, $Message)
    Add-Content -Path $script:LogPath -Value $line -Encoding UTF8
}

# Eventuele generieke Write-Log alias (niet vereist door onze code, maar handig)
Set-Alias -Name Write-Log -Value Write-LogMJ -Scope Global -ErrorAction SilentlyContinue

Export-ModuleMember -Function Set-LogPath, Write-LogMJ

# modules\domainsettingsMJ.psm1  (PS 5.1, ASCII)

if (-not (Get-Command Write-LogMJ -ErrorAction SilentlyContinue)) {
    throw "Write-LogMJ niet gevonden. Importeer modules\loggingMJ.psm1 voor deze module."
}

function Get-DomainConfig {
    $xmlPath = Join-Path $PSScriptRoot '..\settings\Domain.Settings.xml'
    if (-not (Test-Path $xmlPath)) { throw "Domain.Settings.xml niet gevonden: $xmlPath" }
    [xml]$cfg = Get-Content -Path $xmlPath -Raw

    $fqdn = ($cfg.Settings.Domain.domainname).Trim()
    if ([string]::IsNullOrWhiteSpace($fqdn)) { throw "Lege domainname in Domain.Settings.xml" }
    $dn   = ($fqdn -split '\.') | ForEach-Object { "DC=$_" } -join ','
    $netbios = ($cfg.Settings.Domain.domainNetbiosName).Trim()
    $fs      = ($cfg.Settings.FileServer.name).Trim()

    [pscustomobject]@{
        Fqdn       = $fqdn
        Dn         = $dn
        NetBIOS    = $netbios
        FileServer = $fs
        HomeLoc    = $cfg.Settings.UserSettings.homeFolder.location
        HomeShare  = $cfg.Settings.UserSettings.homeFolder.sharename
        HomeDrive  = $cfg.Settings.UserSettings.homeFolder.homeDrive
        ProfLoc    = $cfg.Settings.UserSettings.profileFolder.location
        ProfShare  = $cfg.Settings.UserSettings.profileFolder.sharename
        DefaultPw  = $cfg.Settings.UserSettings.defaultPassword
        XmlPath    = $xmlPath
    }
}

function Install-DomainController {
    Import-Module ServerManager -ErrorAction SilentlyContinue
    try { $conf = Get-DomainConfig } catch { Write-LogMJ "FOUT domeinconfig: $_"; return }

    try {
        $need = @('AD-Domain-Services','RSAT-AD-PowerShell')
        foreach ($f in $need) {
            $feat = Get-WindowsFeature $f
            if ($feat -and $feat.InstallState -ne 'Installed') {
                Install-WindowsFeature $f -IncludeManagementTools | Out-Null
                Write-LogMJ "Feature geinstalleerd: $f"
            }
        }
    } catch { Write-LogMJ "FOUT features: $($_.Exception.Message)"; return }

    [xml]$cfg  = Get-Content $conf.XmlPath
    $safePlain = "$($cfg.Settings.Domain.safeModePassword)"
    if ([string]::IsNullOrWhiteSpace($safePlain)) {
        $safePwd = Read-Host "Voer DSRM (Safe Mode) wachtwoord in" -AsSecureString
    } else {
        $safePwd = ConvertTo-SecureString $safePlain -AsPlainText -Force
    }

    $domainBestaat = $false
    try { $null = Get-ADDomain -Server $conf.Fqdn -ErrorAction Stop; $domainBestaat = $true; Write-LogMJ "Domein bestaat: $($conf.Fqdn)" }
    catch { Write-LogMJ "Geen bestaand domein gevonden: $($conf.Fqdn). Nieuw forest zal worden aangemaakt." }

    try {
        if ($domainBestaat) {
            Install-ADDSDomainController -DomainName $conf.Fqdn -SafeModeAdministratorPassword $safePwd -InstallDNS:$true -NoRebootOnCompletion:$true -Force
            Write-LogMJ "Gepromoveerd tot extra DC in: $($conf.Fqdn)"
        } else {
            Install-ADDSForest -DomainName $conf.Fqdn -SafeModeAdministratorPassword $safePwd -InstallDNS:$true -NoRebootOnCompletion:$true -Force
            Write-LogMJ "Nieuw forest + eerste DC aangemaakt: $($conf.Fqdn)"
        }

        if (-not (Get-Command Enable-MenuAutostart -ErrorAction SilentlyContinue)) {
            . (Join-Path $PSScriptRoot 'algemeenMJ.psm1') | Out-Null
        }
        Enable-MenuAutostart
        Write-LogMJ "RunOnce voor menu gezet (na DC-reboot)."
        shutdown /r /t 5
    } catch {
        Write-LogMJ "FOUT ADDS-promotie: $($_.Exception.Message)"
    }
}

function New-OrganizationalUnits {
    $csvPath = Join-Path $PSScriptRoot '..\settings\ous.csv'
    if (-not (Test-Path $csvPath)) { Write-LogMJ "FOUT: ous.csv niet gevonden: $csvPath"; return }
    try { $conf = Get-DomainConfig } catch { Write-LogMJ $_; return }

    $rows = Import-Csv -Path $csvPath -Delimiter ';'
    foreach ($r in $rows) {
        $ouName    = ("$($r.Name)").Trim()
        $ouPathRaw = ("$($r.Path)").Trim()
        if ([string]::IsNullOrWhiteSpace($ouName)) { Write-LogMJ "Lege OU-naam overgeslagen."; continue }

        $parent = $conf.Dn
        if ($ouPathRaw) {
            $segments = $ouPathRaw -split '[\/,]' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
            foreach ($seg in $segments) {
                $segDn = "OU=$seg,$parent"
                if (-not (Get-ADOrganizationalUnit -LDAPFilter "(distinguishedName=$segDn)" -ErrorAction SilentlyContinue)) {
                    try { New-ADOrganizationalUnit -Name $seg -Path $parent -ProtectedFromAccidentalDeletion $false; Write-LogMJ "OU aangemaakt: $seg onder $parent" }
                    catch { Write-LogMJ "FOUT OU '$seg' onder ${parent}: $($_.Exception.Message)" }
                }
                $parent = $segDn
            }
        }

        $ouDn = "OU=$ouName,$parent"
        if (-not (Get-ADOrganizationalUnit -LDAPFilter "(distinguishedName=$ouDn)" -ErrorAction SilentlyContinue)) {
            try { New-ADOrganizationalUnit -Name $ouName -Path $parent -ProtectedFromAccidentalDeletion $false; Write-LogMJ "OU aangemaakt: ${ouDn}" }
            catch { Write-LogMJ "FOUT OU '$ouName' onder ${parent}: $($_.Exception.Message)" }
        } else {
            Write-LogMJ "OU bestaat al: ${ouDn}"
        }
    }
}

function New-SecurityGroups {
    $csvPath = Join-Path $PSScriptRoot '..\settings\securitygroups.csv'
    if (-not (Test-Path $csvPath)) { Write-LogMJ "FOUT: securitygroups.csv niet gevonden: $csvPath"; return }
    try { $conf = Get-DomainConfig } catch { Write-LogMJ $_; return }

    $groups = Import-Csv -Path $csvPath -Delimiter ';'
    foreach ($g in $groups) {
        $name = ("$($g.GroepNaam)").Trim()
        $ou   = ("$($g.ou)").Trim()
        if ([string]::IsNullOrWhiteSpace($name) -or [string]::IsNullOrWhiteSpace($ou)) { Write-LogMJ "Lege groepsnaam/OU overgeslagen."; continue }

        $parent = $conf.Dn
        $segments = $ou -split '[\/,]' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
        foreach ($seg in $segments) {
            $segDn = "OU=$seg,$parent"
            if (-not (Get-ADOrganizationalUnit -LDAPFilter "(distinguishedName=$segDn)" -ErrorAction SilentlyContinue)) {
                try { New-ADOrganizationalUnit -Name $seg -Path $parent -ProtectedFromAccidentalDeletion $false; Write-LogMJ "OU aangemaakt voor groep: $seg" }
                catch { Write-LogMJ "FOUT OU '$seg' voor groep '$name': $($_.Exception.Message)" }
            }
            $parent = $segDn
        }

        $scope = switch -Wildcard ($name) { 'DL_*' { 'DomainLocal' } 'GL_*' { 'Global' } default { 'Global' } }

        if (-not (Get-ADGroup -LDAPFilter "(cn=$name)" -SearchBase $parent -ErrorAction SilentlyContinue)) {
            try { New-ADGroup -Name $name -GroupScope $scope -GroupCategory Security -Path $parent; Write-LogMJ "Groep aangemaakt: $name ($scope) in $parent" }
            catch { Write-LogMJ "FOUT groep '$name': $($_.Exception.Message)" }
        } else { Write-LogMJ "Groep bestaat al: $name in $parent" }
    }
}

function New-DomainUsers {
    $jsonPath = Join-Path $PSScriptRoot '..\settings\users.json'
    if (-not (Test-Path $jsonPath)) { Write-LogMJ "FOUT: users.json niet gevonden: $jsonPath"; return }
    try { $conf = Get-DomainConfig } catch { Write-LogMJ $_; return }

    $users = (Get-Content $jsonPath -Raw | ConvertFrom-Json).users
    $homeDrive = $conf.HomeDrive; if ($homeDrive -notmatch ':$') { $homeDrive = "${homeDrive}:" }

    foreach ($u in $users) {
        $sam   = $u.login
        $first = $u.firstName
        $last  = $u.lastName
        $ou    = $u.ou
        $full  = "$first $last"

        $parent = $conf.Dn
        $segments = $ou -split '[\/,]' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
        foreach ($seg in $segments) {
            $segDn = "OU=$seg,$parent"
            if (-not (Get-ADOrganizationalUnit -LDAPFilter "(distinguishedName=$segDn)" -ErrorAction SilentlyContinue)) {
                try { New-ADOrganizationalUnit -Name $seg -Path $parent -ProtectedFromAccidentalDeletion $false } catch {}
            }
            $parent = $segDn
        }
        $ouDn = $parent
        $upn  = "$sam@$($conf.Fqdn)"

        $homeUNC    = "\\$($conf.FileServer)\$($conf.HomeShare)\$sam"
        $profileUNC = "\\$($conf.FileServer)\$($conf.ProfShare)\$sam"

        foreach ($root in @($conf.HomeLoc, $conf.ProfLoc)) {
            if ($root) { New-Item -ItemType Directory -Path (Join-Path $root $sam) -Force -ErrorAction SilentlyContinue | Out-Null }
        }

        if (Get-ADUser -LDAPFilter "(sAMAccountName=$sam)" -ErrorAction SilentlyContinue) { Write-LogMJ "Gebruiker bestaat al: $sam"; continue }

        try {
            New-ADUser -Name $full -GivenName $first -Surname $last -SamAccountName $sam -UserPrincipalName $upn `
                -Path $ouDn -Enabled $true -ChangePasswordAtLogon $false `
                -AccountPassword (ConvertTo-SecureString $conf.DefaultPw -AsPlainText -Force) `
                -HomeDirectory $homeUNC -HomeDrive $homeDrive -ProfilePath $profileUNC
            Write-LogMJ "Gebruiker aangemaakt: $sam ($full) in $ouDn"
        } catch { Write-LogMJ "FOUT user '$sam': $($_.Exception.Message)" }
    }
}

function Add-UsersToSecurityGroups {
    $jsonPath = Join-Path $PSScriptRoot '..\settings\users.json'
    if (-not (Test-Path $jsonPath)) { Write-LogMJ "FOUT: users.json niet gevonden: $jsonPath"; return }

    $users = (Get-Content $jsonPath -Raw | ConvertFrom-Json).users
    foreach ($u in $users) {
        $sam = $u.login
        $usr = Get-ADUser -LDAPFilter "(sAMAccountName=$sam)" -ErrorAction SilentlyContinue
        if (-not $usr) { Write-LogMJ "Gebruiker niet gevonden: $sam"; continue }

        foreach ($grp in $u.securityGroups) {
            $g = Get-ADGroup -LDAPFilter "(cn=$grp)" -ErrorAction SilentlyContinue
            if (-not $g) { Write-LogMJ "Groep niet gevonden: $grp (user $sam)"; continue }

            $already = Get-ADGroupMember -Identity $g.DistinguishedName -Recursive -ErrorAction SilentlyContinue |
                       Where-Object { $_.SamAccountName -eq $sam }
            if ($already) { Write-LogMJ "$sam is al lid van $grp"; continue }

            try { Add-ADGroupMember -Identity $g.DistinguishedName -Members $usr.DistinguishedName -ErrorAction Stop; Write-LogMJ "$sam -> $grp" }
            catch { Write-LogMJ "FOUT lidmaatschap $sam -> $grp : $($_.Exception.Message)" }
        }
    }
}

function New-FolderStructure {
    $pathFile = Join-Path $PSScriptRoot '..\settings\mappen.txt'
    if (-not (Test-Path $pathFile)) { Write-LogMJ "FOUT: mappen.txt niet gevonden: $pathFile"; return }

    Get-Content -Path $pathFile | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object {
        $p = $_.Trim()
        if (-not (Test-Path $p)) {
            try { New-Item -Path $p -ItemType Directory -Force | Out-Null; Write-LogMJ "Map aangemaakt: $p" }
            catch { Write-LogMJ "FOUT map '$p': $($_.Exception.Message)" }
        } else { Write-LogMJ "Map bestaat al: $p" }
    }
}

function New-NetworkShares {
    $csvPath = Join-Path $PSScriptRoot '..\settings\shares.csv'
    if (-not (Test-Path $csvPath)) { Write-LogMJ "FOUT: shares.csv niet gevonden: $csvPath"; return }

    $rows = Import-Csv -Path $csvPath -Delimiter ';'
    foreach ($r in $rows) {
        $folder = ("$($r.map)").Trim()
        $name   = ("$($r.share)").Trim()
        if ([string]::IsNullOrWhiteSpace($folder) -or [string]::IsNullOrWhiteSpace($name)) { Write-LogMJ "Lege map/share overgeslagen"; continue }

        if (-not (Test-Path $folder)) {
            try { New-Item -Path $folder -ItemType Directory -Force | Out-Null; Write-LogMJ "Map aangemaakt voor share: $folder" }
            catch { Write-LogMJ "FOUT map '$folder': $($_.Exception.Message)"; continue }
        }

        if (-not (Get-SmbShare -Name $name -ErrorAction SilentlyContinue)) {
            try { New-SmbShare -Name $name -Path $folder -FullAccess 'BUILTIN\Administrators' | Out-Null; Write-LogMJ "Share aangemaakt: $name -> $folder" }
            catch { Write-LogMJ "FOUT share '$name': $($_.Exception.Message)" }
        } else { Write-LogMJ "Share bestaat al: $name" }
    }
}

function Set-NTFSPermissions {
    $csvPath = Join-Path $PSScriptRoot '..\settings\rechten.csv'
    if (-not (Test-Path $csvPath)) { Write-LogMJ "FOUT: rechten.csv niet gevonden: $csvPath"; return }
    try { $conf = Get-DomainConfig } catch { Write-LogMJ $_; return }

    $rows = Import-Csv -Path $csvPath -Delimiter ';'
    foreach ($r in $rows) {
        $folder = ("$($r.map)").Trim()
        $share  = ("$($r.share)").Trim()
        $grp    = ("$($r.Groep)").Trim()
        $ntfs   = ("$($r.NTFS_permission)").Trim().ToLower()
        $sperm  = ("$($r.share_permission)").Trim().ToLower()

        $adg = Get-ADGroup -LDAPFilter "(cn=$grp)" -ErrorAction SilentlyContinue
        if (-not $adg) { Write-LogMJ "Groep ontbreekt: $grp -> rij overgeslagen"; continue }

        if (Test-Path $folder) {
            try {
                $acl = Get-Acl $folder
                $rights = switch ($ntfs) {
                    'read'   { [System.Security.AccessControl.FileSystemRights]::ReadAndExecute }
                    'modify' { [System.Security.AccessControl.FileSystemRights]::Modify }
                    'full'   { [System.Security.AccessControl.FileSystemRights]::FullControl }
                    default  { [System.Security.AccessControl.FileSystemRights]::ReadAndExecute }
                }
                $id = "$($conf.NetBIOS)\$grp"

                $existing = $acl.Access | Where-Object { $_.IdentityReference -eq $id }
                foreach ($ace in $existing) { $null = $acl.RemoveAccessRule($ace) }

                $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($id, $rights, 'ContainerInherit,ObjectInherit', 'None', 'Allow')
                $acl.AddAccessRule($rule)
                Set-Acl -Path $folder -AclObject $acl
                Write-LogMJ "NTFS '$ntfs' op $folder voor $id"
            } catch { Write-LogMJ "FOUT NTFS $folder / ${grp}: $($_.Exception.Message)" }
        } else { Write-LogMJ "Map niet gevonden, NTFS overgeslagen: $folder" }

        $s = Get-SmbShare -Name $share -ErrorAction SilentlyContinue
        if ($s) {
            try {
                $access = switch ($sperm) { 'read' { 'Read' } 'change' { 'Change' } 'full' { 'Full' } default { 'Read' } }
                $id = "$($conf.NetBIOS)\$grp"
                Revoke-SmbShareAccess -Name $share -AccountName $id -Force -Confirm:$false -ErrorAction SilentlyContinue
                Grant-SmbShareAccess  -Name $share -AccountName $id -AccessRight $access -Force
                Write-LogMJ "Share '$share' -> $id : $sperm"
            } catch { Write-LogMJ "FOUT share access $share / ${grp}: $($_.Exception.Message)" }
        } else { Write-LogMJ "Share ontbreekt: $share (groep $grp)" }
    }
}

Export-ModuleMember -Function Install-DomainController, New-OrganizationalUnits, New-SecurityGroups, New-DomainUsers, Add-UsersToSecurityGroups, New-FolderStructure, New-NetworkShares, Set-NTFSPermissions

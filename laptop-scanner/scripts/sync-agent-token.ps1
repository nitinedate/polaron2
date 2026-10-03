# Links this laptop to Service 3 with the same emailed access token as the web UIs.
# 1) Always prompt for the access token from the Aetheris login email.
# 2) Token-login; refuse to link if that fails.
# 3) Bind AGENT_TOKEN to that same emailed token.

function Get-Utf8NoBom {
    New-Object System.Text.UTF8Encoding $false
}

function Get-ApiRoot([string]$Base) {
    $rootUrl = ($Base | ForEach-Object { $_.Trim().TrimEnd('/') })
    if ($rootUrl -match 'host\.docker\.internal') {
        $rootUrl = $rootUrl -replace 'host\.docker\.internal', '127.0.0.1'
    }
    if ($rootUrl.ToLower().EndsWith('/api')) {
        $rootUrl = $rootUrl.Substring(0, $rootUrl.Length - 4).TrimEnd('/')
    }
    return $rootUrl
}

function Get-CurlInsecureArgs([hashtable]$EnvMap) {
    $raw = ([string]$EnvMap['VERIFY_TLS']).Trim().ToLower()
    if ($raw -in @('0', 'false', 'no', 'off')) { return @('-k') }
    return @()
}

function Read-TokenFile([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return '' }
    $bytes = [IO.File]::ReadAllBytes($Path)
    if ($bytes.Length -eq 0) { return '' }
    $text = ''
    if ($bytes.Length -ge 2 -and $bytes[0] -eq 255 -and $bytes[1] -eq 254) {
        $text = [Text.Encoding]::Unicode.GetString($bytes, 2, $bytes.Length - 2)
    } elseif ($bytes.Length -ge 3 -and $bytes[0] -eq 239 -and $bytes[1] -eq 187 -and $bytes[2] -eq 191) {
        $text = [Text.Encoding]::UTF8.GetString($bytes, 3, $bytes.Length - 3)
    } else {
        $nulCount = 0
        foreach ($b in $bytes) { if ($b -eq 0) { $nulCount++ } }
        if ($nulCount -gt ($bytes.Length / 4)) {
            $text = [Text.Encoding]::Unicode.GetString($bytes)
        } else {
            $text = [Text.Encoding]::UTF8.GetString($bytes)
        }
    }
    return ($text.Trim())
}

function Set-DotEnvValue([string]$Path, [string]$Key, [string]$Value) {
    $lines = @()
    if (Test-Path -LiteralPath $Path) {
        $lines = [IO.File]::ReadAllLines($Path)
    }
    $found = $false
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($line in $lines) {
        if ($line -match ('^\s*' + [regex]::Escape($Key) + '\s*=')) {
            if (-not $found) {
                $out.Add("$Key=$Value")
                $found = $true
            }
        } else {
            $out.Add($line)
        }
    }
    if (-not $found) { $out.Add("$Key=$Value") }
    [IO.File]::WriteAllLines($Path, $out.ToArray(), (Get-Utf8NoBom))
}

function Save-AgentToken {
    param(
        [string]$Root,
        [string]$EnvPath,
        [string]$Token
    )
    $token = ($Token | ForEach-Object { $_.Trim() })
    if ([string]::IsNullOrWhiteSpace($token)) { throw 'Refusing to save an empty AGENT_TOKEN.' }
    $tokenFile = Join-Path $Root 'scanner-agent\.agent-token'
    $tokenDir = Split-Path $tokenFile
    if (-not (Test-Path -LiteralPath $tokenDir)) {
        New-Item -ItemType Directory -Force -Path $tokenDir | Out-Null
    }
    [IO.File]::WriteAllText($tokenFile, $token + [Environment]::NewLine, (Get-Utf8NoBom))
    Set-DotEnvValue -Path $EnvPath -Key 'AGENT_TOKEN' -Value $token
    # The running Docker stack bind-mounts E:\laptop-scanner. If Start-Laptop
    # was launched from D: or another copy, still update the live token file.
    foreach ($liveRoot in @('E:\laptop-scanner', 'D:\laptop-scanner')) {
        if ($liveRoot -eq $Root) { continue }
        $liveEnv = Join-Path $liveRoot '.env'
        $liveToken = Join-Path $liveRoot 'scanner-agent\.agent-token'
        if (-not (Test-Path -LiteralPath $liveEnv)) { continue }
        Set-DotEnvValue -Path $liveEnv -Key 'AGENT_TOKEN' -Value $token
        $liveDir = Split-Path $liveToken
        if (-not (Test-Path -LiteralPath $liveDir)) {
            New-Item -ItemType Directory -Force -Path $liveDir | Out-Null
        }
        [IO.File]::WriteAllText($liveToken, $token + [Environment]::NewLine, (Get-Utf8NoBom))
        Write-Host "[OK] Also wrote AGENT_TOKEN to $liveRoot so the running stack can claim jobs."
    }
}

function Invoke-JsonApi {
    param(
        [string]$Method,
        [string]$Url,
        [string]$Tenant,
        [string]$AccessToken,
        $BodyObject,
        [string[]]$InsecureArgs
    )
    if (-not (Get-Command curl.exe -ErrorAction SilentlyContinue)) {
        throw 'curl.exe is required for laptop authentication.'
    }
    $bodyFile = [IO.Path]::GetTempFileName()
    $outFile = [IO.Path]::GetTempFileName()
    try {
        $curlArgs = @()
        if ($InsecureArgs) { $curlArgs += $InsecureArgs }
        $curlArgs += @('-sS', '-o', $outFile, '-w', '%{http_code}', '-X', $Method, $Url, '-H', "X-Tenant: $Tenant", '--connect-timeout', '20', '--max-time', '45')
        if ($AccessToken) { $curlArgs += @('-H', "Authorization: Bearer $AccessToken") }
        if ($null -ne $BodyObject) {
            [IO.File]::WriteAllText($bodyFile, ($BodyObject | ConvertTo-Json -Compress -Depth 8), (Get-Utf8NoBom))
            $curlArgs += @('-H', 'Content-Type: application/json', '--data-binary', "@$bodyFile")
        }
        $codeText = & curl.exe @curlArgs 2>$null
        if ($LASTEXITCODE -ne 0) {
            return [pscustomobject]@{ Status = -1; Body = '' }
        }
        $status = 0
        [void][int]::TryParse([string]$codeText, [ref]$status)
        $body = ''
        if (Test-Path -LiteralPath $outFile) {
            $body = [IO.File]::ReadAllText($outFile)
        }
        return [pscustomobject]@{ Status = $status; Body = $body }
    } finally {
        Remove-Item -Force $bodyFile, $outFile -ErrorAction SilentlyContinue
    }
}

function Test-AgentToken {
    param(
        [string]$Base,
        [string]$Tenant,
        [string]$Token,
        [string[]]$InsecureArgs
    )
    if ([string]::IsNullOrWhiteSpace($Token) -or $Token -eq 'replace-me') { return 0 }
    $rootUrl = Get-ApiRoot $Base
    $hb = Invoke-JsonApi -Method 'POST' -Url ($rootUrl + '/api/scanner-agent/heartbeat') -Tenant $Tenant -AccessToken $Token -BodyObject @{} -InsecureArgs $InsecureArgs
    if ($hb.Status -ge 200 -and $hb.Status -lt 300) { return $hb.Status }
    if ($hb.Status -eq 401 -or $hb.Status -eq 403) { return $hb.Status }
    $jobs = Invoke-JsonApi -Method 'GET' -Url ($rootUrl + '/api/scanner-agent/jobs/next') -Tenant $Tenant -AccessToken $Token -BodyObject $null -InsecureArgs $InsecureArgs
    if ($jobs.Status -eq 401 -or $jobs.Status -eq 403) { return $jobs.Status }
    if ($hb.Status -ne -1 -and $hb.Status -ne 0) { return $hb.Status }
    return $jobs.Status
}

function Add-TokenCandidate {
    param(
        $List,
        [string]$Source,
        [string]$Value
    )
    $v = ([string]$Value).Trim()
    if ([string]::IsNullOrWhiteSpace($v) -or $v -eq 'replace-me') { return }
    foreach ($existing in $List) {
        if ($existing.Value -eq $v) { return }
    }
    $List.Add([pscustomobject]@{ Source = $Source; Value = $v })
}

function Get-LocalTokenCandidates {
    param(
        [string]$Root,
        [hashtable]$EnvMap
    )
    $list = New-Object System.Collections.Generic.List[object]
    Add-TokenCandidate $list 'AGENT_TOKEN (.env)' ([string]$EnvMap['AGENT_TOKEN'])
    Add-TokenCandidate $list 'scanner-agent/.agent-token' (Read-TokenFile (Join-Path $Root 'scanner-agent\.agent-token'))
    Add-TokenCandidate $list 'AGENT_RECOVERY_TOKEN (.env)' ([string]$EnvMap['AGENT_RECOVERY_TOKEN'])
    Add-TokenCandidate $list 'scanner-agent/.agent-recovery-token' (Read-TokenFile (Join-Path $Root 'scanner-agent\.agent-recovery-token'))
    return $list
}

function ConvertFrom-JsonSafe([string]$Text) {
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    try {
        return ($Text | ConvertFrom-Json)
    } catch {
        return $null
    }
}

function Resolve-LoginEmail {
    param(
        [string]$UserName,
        [string]$Domain = ''
    )
    $user = ([string]$UserName).Trim()
    $dom = ([string]$Domain).Trim()
    if ($user -match '\\') {
        $parts = $user -split '\\', 2
        if ($parts.Count -eq 2) {
            $dom = $parts[0]
            $user = $parts[1]
        }
    }
    # Windows credential dialog splits name@company.com into User=name, Domain=company.com.
    if ($user -notmatch '@' -and $dom -match '\.') {
        $user = "$user@$dom"
    }
    return $user.Trim().ToLower()
}

function Read-ConsoleSecret([string]$Prompt) {
    $secure = Read-Host $Prompt -AsSecureString
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try {
        return [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
    } finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
}

function Get-ApiErrorText($Response) {
    if ($null -eq $Response) { return '' }
    $json = ConvertFrom-JsonSafe ([string]$Response.Body)
    $candidates = @(
        [string]$json.detail.error.message,
        [string]$json.detail.message,
        [string]$json.error.message,
        [string]$json.message
    )
    foreach ($msg in $candidates) {
        if (-not [string]::IsNullOrWhiteSpace($msg)) { return $msg.Trim() }
    }
    $snip = ([string]$Response.Body).Trim()
    if ($snip.Length -gt 180) { $snip = $snip.Substring(0, 180) }
    return $snip
}

function Get-ClientAccessTokenPrompt {
    param(
        [string]$Tenant
    )
    if (-not [Environment]::UserInteractive) {
        throw 'Start-Laptop must run interactively so it can ask for the access token from the Aetheris login email.'
    }
    Write-Host ''
    Write-Host 'The emailed access token is required before this laptop can link to the server.'
    Write-Host "On any Aetheris login page, request a token for organization $Tenant, then paste it here."
    Write-Host 'The same token signs into Forensic, Mobile extract, and this laptop scanner.'
    Write-Host 'Stored AGENT_TOKEN in .env is not enough to skip this prompt.'
    Write-Host ''
    $token = (Read-Host 'Access token from login email').Trim()
    if ([string]::IsNullOrWhiteSpace($token)) {
        throw 'Access token was empty. Re-run Start-Laptop and paste the token from the login email.'
    }
    return $token
}

function Get-ClientSessionToken {
    param(
        [string]$Base,
        [string]$Tenant,
        [string]$ClientToken,
        [string[]]$InsecureArgs
    )
    $rootUrl = Get-ApiRoot $Base
    Write-Host ("[INFO] Signing in with the emailed access token (organization {0})." -f $Tenant)
    $login = Invoke-JsonApi -Method 'POST' -Url ($rootUrl + '/api/auth/token-login') -Tenant $Tenant -AccessToken $null -BodyObject @{ token = $ClientToken } -InsecureArgs $InsecureArgs
    if ($login.Status -lt 200 -or $login.Status -ge 300) {
        $detail = Get-ApiErrorText $login
        if ($detail) {
            throw "Token login failed (HTTP $($login.Status)): $detail. Check TENANT_SLUG=$Tenant and the token from the login email for $Base"
        }
        throw "Token login failed (HTTP $($login.Status)). Check TENANT_SLUG and the emailed access token for $Base"
    }
    $json = ConvertFrom-JsonSafe $login.Body
    if ($null -eq $json) { throw 'Token login returned an unreadable response.' }
    $access = [string]$json.access_token
    if ([string]::IsNullOrWhiteSpace($access)) {
        throw 'Token login did not return a session token.'
    }
    return $access
}

function Select-EdgeScanner {
    param(
        $Items,
        [hashtable]$EnvMap,
        [string]$Computer
    )
    $edge = @($Items | Where-Object {
        $mode = ([string]$_.connection_mode).ToLower()
        $url = ([string]$_.url).ToLower()
        $role = ([string]$_.scanner_role).ToLower()
        $mode -eq 'edge_agent' -or $url.StartsWith('agent://') -or $role -in @('portable', 'persistent_edge')
    })
    if ($edge.Count -eq 0) { return $null }
    $id = ([string]$EnvMap['SCANNER_ID']).Trim()
    if ($id) {
        $hit = @($edge | Where-Object { [string]$_.id -eq $id } | Select-Object -First 1)
        if ($hit) { return $hit }
    }
    $wantName = ([string]$EnvMap['SCANNER_NAME']).Trim()
    if (-not $wantName) { $wantName = "Laptop-$Computer" }
    $hit = @($edge | Where-Object { [string]$_.name -eq $wantName } | Select-Object -First 1)
    if ($hit) { return $hit }
    $role = ([string]$EnvMap['SCANNER_ROLE']).Trim()
    if (-not $role) { $role = 'portable' }
    $byRole = @($edge | Where-Object { ([string]$_.scanner_role).ToLower() -eq $role.ToLower() })
    $byName = @($edge | Where-Object { ([string]$_.name).ToLower() -eq 'laptop' -or ([string]$_.name -like 'Laptop-*') })
    if ($byName.Count -eq 1) { return $byName[0] }
    if ($byRole.Count -eq 1) { return $byRole[0] }
    if ($edge.Count -eq 1) { return $edge[0] }
    return $null
}

function Bind-EdgeScannerToken {
    param(
        [string]$Base,
        [string]$Tenant,
        [string]$AccessToken,
        [string]$ClientToken,
        [hashtable]$EnvMap,
        [string[]]$InsecureArgs,
        [string]$EnvPath
    )
    $rootUrl = Get-ApiRoot $Base
    $computer = $env:COMPUTERNAME
    $role = ([string]$EnvMap['SCANNER_ROLE']).Trim()
    if (-not $role) { $role = 'portable' }
    $name = ([string]$EnvMap['SCANNER_NAME']).Trim()
    if (-not $name) { $name = "Laptop-$computer" }
    $sid = ([string]$EnvMap['SCANNER_ID']).Trim()
    Write-Host ("[OK] Binding laptop scanner '{0}' to the emailed access token." -f $name)
    $body = @{
        token = $ClientToken
        name = $name
        scanner_role = $role
    }
    if ($sid) { $body.scanner_id = $sid }
    $bound = Invoke-JsonApi -Method 'POST' -Url ($rootUrl + '/api/scanners/bind-client-token') -Tenant $Tenant -AccessToken $AccessToken -BodyObject $body -InsecureArgs $InsecureArgs
    if ($bound.Status -eq 403) {
        throw 'Logged-in user cannot manage scanners (needs scan:policy_manage). Use a firm admin account.'
    }
    if ($bound.Status -lt 200 -or $bound.Status -ge 300) {
        $detail = Get-ApiErrorText $bound
        if ($detail) { throw "Could not bind the emailed token to this laptop (HTTP $($bound.Status)): $detail" }
        throw "Could not bind the emailed token to this laptop (HTTP $($bound.Status))"
    }
    $json = ConvertFrom-JsonSafe $bound.Body
    $token = [string]$json.agent_token
    if (-not $token) { $token = $ClientToken }
    $newId = [string]$json.id
    if ($newId -and $EnvPath) { Set-DotEnvValue -Path $EnvPath -Key 'SCANNER_ID' -Value $newId }
    return $token
}

function Sync-LaptopAgentToken {
    param(
        [string]$Root,
        [string]$EnvPath,
        [hashtable]$EnvMap
    )
    $central = ([string]$EnvMap['CENTRAL_API_URL']).Trim()
    $tenant = ([string]$EnvMap['TENANT_SLUG']).Trim()
    if ([string]::IsNullOrWhiteSpace($tenant)) { $tenant = 'aetheris' }
    $insecure = Get-CurlInsecureArgs $EnvMap
    $rootUrl = Get-ApiRoot $central
    $health = Invoke-JsonApi -Method 'GET' -Url ($rootUrl + '/api/health') -Tenant $tenant -AccessToken $null -BodyObject $null -InsecureArgs $insecure
    if ($health.Status -eq -1 -or $health.Status -eq 0) {
        throw "Cannot reach CENTRAL_API_URL=$central. Web login and token matching need that API online."
    }
    Write-Host ("[INFO] Central reachable at {0} (HTTP {1}). Asking for the emailed access token." -f $central, $health.Status)
    $clientToken = Get-ClientAccessTokenPrompt -Tenant $tenant
    $access = Get-ClientSessionToken -Base $central -Tenant $tenant -ClientToken $clientToken -InsecureArgs $insecure
    Write-Host '[OK] Token login accepted. Binding this laptop to the same access token.'
    $token = Bind-EdgeScannerToken -Base $central -Tenant $tenant -AccessToken $access -ClientToken $clientToken -EnvMap $EnvMap -InsecureArgs $insecure -EnvPath $EnvPath
    Save-AgentToken -Root $Root -EnvPath $EnvPath -Token $token
    $confirm = Test-AgentToken -Base $central -Tenant $tenant -Token $token -InsecureArgs $insecure
    if ($confirm -lt 200 -or $confirm -ge 300) {
        throw "Central bound the token but heartbeat still failed (HTTP $confirm)."
    }
    Write-Host '[OK] Laptop scanner is linked with the same emailed token used on the web UIs.' -ForegroundColor Green
    return $token
}

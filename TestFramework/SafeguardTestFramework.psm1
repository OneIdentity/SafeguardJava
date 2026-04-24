#Requires -Version 7.0
<#
.SYNOPSIS
    SafeguardJava Test Framework Module

.DESCRIPTION
    Provides test context management, assertion functions, Java tool invocation,
    cleanup registration, and structured reporting for SafeguardJava integration tests.

    All tests run against a live Safeguard appliance. This module invokes the
    SafeguardJavaTool CLI via java -jar with proper process management.

    All exported functions use the SgJ noun prefix to avoid conflicts.
#>

# ============================================================================
# Module-scoped state
# ============================================================================

$script:TestContext = $null

# ============================================================================
# Context Management
# ============================================================================

function New-SgJTestContext {
    <#
    .SYNOPSIS
        Creates a new test context tracking appliance info, credentials, results, and cleanup.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Appliance,

        [Parameter()]
        [string]$AdminUserName = "admin",

        [Parameter()]
        [string]$AdminPassword = "Admin123",

        [Parameter()]
        [string]$SpsAppliance,

        [Parameter()]
        [string]$SpsUserName,

        [Parameter()]
        [string]$SpsPassword,

        [Parameter()]
        [string]$TestPrefix = "SgJTest",

        [Parameter()]
        [string]$MavenCmd,

        [Parameter()]
        [switch]$Pkce
    )

    $repoRoot = Split-Path -Parent $PSScriptRoot
    $testDataDir = Join-Path $PSScriptRoot "TestData" "CERTS"
    $context = [PSCustomObject]@{
        # Connection info
        Appliance       = $Appliance
        AdminUserName   = $AdminUserName
        AdminPassword   = $AdminPassword

        # SPS connection info
        SpsAppliance    = $SpsAppliance
        SpsUserName     = $SpsUserName
        SpsPassword     = $SpsPassword

        # Certificate test data paths
        UserPfx         = (Join-Path $testDataDir "UserCert.pfx")
        UserCert        = (Join-Path $testDataDir "UserCert.pem")
        RootCert        = (Join-Path $testDataDir "RootCA.pem")
        CaCert          = (Join-Path $testDataDir "IntermediateCA.pem")

        # Naming
        TestPrefix      = $TestPrefix

        # Paths
        RepoRoot        = $repoRoot
        TestRoot        = $PSScriptRoot
        ToolDir         = (Join-Path $repoRoot "tests" "safeguardjavaclient")
        MavenCmd        = $MavenCmd
        Pkce            = [bool]$Pkce

        # Per-suite transient data (reset each suite)
        SuiteData       = @{}

        # Cleanup stack (LIFO)
        CleanupActions  = [System.Collections.Generic.Stack[PSCustomObject]]::new()

        # Results
        SuiteResults    = [System.Collections.Generic.List[PSCustomObject]]::new()
        StartTime       = [DateTime]::UtcNow
    }

    $script:TestContext = $context
    return $context
}

function Get-SgJTestContext {
    <#
    .SYNOPSIS
        Returns the current module-scoped test context.
    #>
    if (-not $script:TestContext) {
        throw "No test context. Call New-SgJTestContext first."
    }
    return $script:TestContext
}

# ============================================================================
# Cleanup Registration
# ============================================================================

function Register-SgJTestCleanup {
    <#
    .SYNOPSIS
        Registers an idempotent cleanup action that runs during suite cleanup.
        Actions execute in LIFO order. Failures are logged but do not propagate.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Description,

        [Parameter(Mandatory)]
        [scriptblock]$Action
    )

    $ctx = Get-SgJTestContext
    $ctx.CleanupActions.Push([PSCustomObject]@{
        Description = $Description
        Action      = $Action
    })
}

function Invoke-SgJTestCleanup {
    <#
    .SYNOPSIS
        Executes all registered cleanup actions in LIFO order.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Context
    )

    $count = $Context.CleanupActions.Count
    if ($count -eq 0) {
        Write-Host "  No cleanup actions registered." -ForegroundColor DarkGray
        return
    }

    Write-Host "  Running $count cleanup action(s)..." -ForegroundColor DarkGray
    while ($Context.CleanupActions.Count -gt 0) {
        $item = $Context.CleanupActions.Pop()
        try {
            Write-Host "    Cleanup: $($item.Description)" -ForegroundColor DarkGray
            & $item.Action $Context
        }
        catch {
            Write-Host "    Cleanup ignored failure: $($_.Exception.Message)" -ForegroundColor DarkYellow
        }
    }
}

# ============================================================================
# SafeguardJavaTool Invocation
# ============================================================================

function Invoke-SgJSafeguardTool {
    <#
    .SYNOPSIS
        Runs the SafeguardJavaTool via java -jar with proper process management.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Arguments,

        [Parameter()]
        [string]$StdinLine,

        [Parameter()]
        [bool]$ParseJson = $true,

        [Parameter()]
        [int]$TimeoutSeconds = 120
    )

    $ctx = Get-SgJTestContext

    $jarPath = Join-Path $ctx.ToolDir "target" "safeguardjavaclient-1.0-SNAPSHOT.jar"
    if (-not (Test-Path $jarPath)) {
        throw "Test tool jar not found at: $jarPath. Run build first."
    }

    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = "java"
    $startInfo.Arguments = "-jar `"$jarPath`" $Arguments"
    $startInfo.UseShellExecute = $false
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.RedirectStandardInput = ($null -ne $StdinLine -and $StdinLine -ne "")
    $startInfo.CreateNoWindow = $true
    $startInfo.WorkingDirectory = $ctx.ToolDir

    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo

    $stdoutBuilder = [System.Text.StringBuilder]::new()
    $stderrBuilder = [System.Text.StringBuilder]::new()

    $stdoutEvent = Register-ObjectEvent -InputObject $process -EventName OutputDataReceived -Action {
        if ($null -ne $EventArgs.Data) {
            $Event.MessageData.AppendLine($EventArgs.Data) | Out-Null
        }
    } -MessageData $stdoutBuilder

    $stderrEvent = Register-ObjectEvent -InputObject $process -EventName ErrorDataReceived -Action {
        if ($null -ne $EventArgs.Data) {
            $Event.MessageData.AppendLine($EventArgs.Data) | Out-Null
        }
    } -MessageData $stderrBuilder

    try {
        $process.Start() | Out-Null
        $process.BeginOutputReadLine()
        $process.BeginErrorReadLine()

        if ($startInfo.RedirectStandardInput) {
            $process.StandardInput.WriteLine($StdinLine)
            $process.StandardInput.Close()
        }

        $exited = $process.WaitForExit($TimeoutSeconds * 1000)
        if (-not $exited) {
            try { $process.Kill() } catch {}
            throw "Process timed out after ${TimeoutSeconds}s"
        }

        $process.WaitForExit()
    }
    finally {
        Unregister-Event -SourceIdentifier $stdoutEvent.Name -ErrorAction SilentlyContinue
        Unregister-Event -SourceIdentifier $stderrEvent.Name -ErrorAction SilentlyContinue
        Remove-Job -Name $stdoutEvent.Name -Force -ErrorAction SilentlyContinue
        Remove-Job -Name $stderrEvent.Name -Force -ErrorAction SilentlyContinue
    }

    $stdout = $stdoutBuilder.ToString().Trim()
    $stderr = $stderrBuilder.ToString().Trim()
    $exitCode = $process.ExitCode
    $process.Dispose()

    if ($exitCode -ne 0) {
        $errorDetail = if ($stderr) { $stderr } elseif ($stdout) { $stdout } else { "Exit code $exitCode" }
        throw "Tool failed (exit code $exitCode): $errorDetail"
    }

    if (-not $ParseJson -or [string]::IsNullOrWhiteSpace($stdout)) {
        return $stdout
    }

    # Parse JSON from stdout, filtering out noise
    $lines = $stdout -split "`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" }

    # Try parsing entire output first
    try {
        return ($stdout | ConvertFrom-Json)
    }
    catch {}

    # Strip leading non-JSON noise and try again
    $jsonStartIndex = -1
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match '^\s*[\[\{"]') {
            $jsonStartIndex = $i
            break
        }
    }
    if ($jsonStartIndex -ge 0) {
        $jsonRegion = ($lines[$jsonStartIndex..($lines.Count - 1)]) -join "`n"
        try {
            return ($jsonRegion | ConvertFrom-Json)
        }
        catch {}
    }

    # Try each line — find the last valid JSON line
    $jsonResult = $null
    foreach ($line in $lines) {
        try {
            $jsonResult = $line | ConvertFrom-Json
        }
        catch {}
    }

    if ($null -ne $jsonResult) {
        return $jsonResult
    }

    return $stdout
}

function Invoke-SgJSafeguardApi {
    <#
    .SYNOPSIS
        Convenience wrapper for calling Safeguard API via SafeguardJavaTool.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [PSCustomObject]$Context,

        [Parameter(Mandatory)]
        [ValidateSet("Core", "Appliance", "Notification", "A2A")]
        [string]$Service,

        [Parameter(Mandatory)]
        [ValidateSet("Get", "Post", "Put", "Delete")]
        [string]$Method,

        [Parameter(Mandatory)]
        [string]$RelativeUrl,

        [Parameter()]
        $Body,

        [Parameter()]
        [string]$Username,

        [Parameter()]
        [string]$Password,

        [Parameter()]
        [switch]$Anonymous,

        [Parameter()]
        [string]$AccessToken,

        [Parameter()]
        [string]$CertificateFile,

        [Parameter()]
        [string]$CertificatePassword,

        [Parameter()]
        [switch]$Pkce,

        [Parameter()]
        [switch]$Full,

        [Parameter()]
        [string]$File,

        [Parameter()]
        [hashtable]$Headers,

        [Parameter()]
        [hashtable]$Parameters,

        [Parameter()]
        [bool]$ParseJson = $true
    )

    if (-not $Context) { $Context = Get-SgJTestContext }

    $toolArgs = "-a $($Context.Appliance) -x -s $Service -m $Method -U `"$RelativeUrl`""

    $stdinLine = $null

    if ($Anonymous) {
        $toolArgs += " -A"
    }
    elseif ($AccessToken) {
        $toolArgs += " -k `"$AccessToken`""
    }
    elseif ($CertificateFile) {
        $toolArgs += " -c `"$CertificateFile`""
        if ($CertificatePassword) {
            $toolArgs += " -p"
            $stdinLine = $CertificatePassword
        }
    }
    else {
        $effectiveUser = if ($Username) { $Username } else { $Context.AdminUserName }
        $effectivePass = if ($Password) { $Password } else { $Context.AdminPassword }
        $provider = "local"
        $toolArgs += " -u $effectiveUser -i $provider -p"
        if ($Pkce) { $toolArgs += " --pkce" }
        $stdinLine = $effectivePass
    }

    if ($Body) {
        $bodyStr = if ($Body -is [hashtable] -or $Body -is [System.Collections.IDictionary] -or $Body -is [PSCustomObject]) {
            (ConvertTo-Json -Depth 12 $Body -Compress).Replace('"', "'")
        }
        else {
            [string]$Body
        }
        $toolArgs += " -b `"$bodyStr`""
    }

    if ($Full) { $toolArgs += " -f" }

    if ($File) { $toolArgs += " -F `"$File`"" }

    if ($Headers -and $Headers.Count -gt 0) {
        $headerPairs = ($Headers.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ","
        $toolArgs += " -H `"$headerPairs`""
    }

    if ($Parameters -and $Parameters.Count -gt 0) {
        $paramPairs = ($Parameters.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ","
        $toolArgs += " -P `"$paramPairs`""
    }

    Write-Verbose "Invoke-SgJSafeguardApi: $toolArgs"

    return Invoke-SgJSafeguardTool -Arguments $toolArgs -StdinLine $stdinLine -ParseJson $ParseJson
}

function Invoke-SgJTokenCommand {
    <#
    .SYNOPSIS
        Runs a token management command via SafeguardJavaTool.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [PSCustomObject]$Context,

        [Parameter(Mandatory)]
        [ValidateSet("TokenLifetime", "GetToken", "RefreshToken", "Logout")]
        [string]$Command,

        [Parameter()]
        [string]$Username,

        [Parameter()]
        [string]$Password,

        [Parameter()]
        [switch]$Pkce
    )

    if (-not $Context) { $Context = Get-SgJTestContext }

    $effectiveUser = if ($Username) { $Username } else { $Context.AdminUserName }
    $effectivePass = if ($Password) { $Password } else { $Context.AdminPassword }

    $toolArgs = "-a $($Context.Appliance) -x -u $effectiveUser -i local -p"
    if ($Pkce) { $toolArgs += " --pkce" }

    switch ($Command) {
        "TokenLifetime" { $toolArgs += " -T" }
        "GetToken"      { $toolArgs += " -G" }
        "RefreshToken"  { $toolArgs += " --refresh-token" }
        "Logout"        { $toolArgs += " -L" }
    }

    return Invoke-SgJSafeguardTool -Arguments $toolArgs -StdinLine $effectivePass
}

function Invoke-SgJSafeguardSessions {
    <#
    .SYNOPSIS
        Convenience wrapper for calling SPS API via SafeguardJavaTool --sps mode.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [PSCustomObject]$Context,

        [Parameter(Mandatory)]
        [ValidateSet("Get", "Post", "Put", "Delete")]
        [string]$Method,

        [Parameter(Mandatory)]
        [string]$RelativeUrl,

        [Parameter()]
        $Body,

        [Parameter()]
        [switch]$Full,

        [Parameter()]
        [bool]$ParseJson = $true
    )

    if (-not $Context) { $Context = Get-SgJTestContext }

    $toolArgs = "-a $($Context.SpsAppliance) -x --sps -m $Method -U `"$RelativeUrl`" -u $($Context.SpsUserName) -p"

    if ($Body) {
        $bodyStr = if ($Body -is [hashtable] -or $Body -is [System.Collections.IDictionary] -or $Body -is [PSCustomObject]) {
            (ConvertTo-Json -Depth 12 $Body -Compress).Replace('"', "'")
        }
        else {
            [string]$Body
        }
        $toolArgs += " -b `"$bodyStr`""
    }

    if ($Full) { $toolArgs += " -f" }

    Write-Verbose "Invoke-SgJSafeguardSessions: $toolArgs"

    return Invoke-SgJSafeguardTool -Arguments $toolArgs -StdinLine $Context.SpsPassword -ParseJson $ParseJson
}

function Invoke-SgJSafeguardA2a {
    <#
    .SYNOPSIS
        Convenience wrapper for calling A2A operations via SafeguardJavaTool.
    .DESCRIPTION
        Creates an A2A context using a client certificate and retrieves retrievable accounts,
        optionally applying a server-side SCIM filter.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [PSCustomObject]$Context,

        [Parameter(Mandatory)]
        [string]$CertificateFile,

        [Parameter()]
        [string]$CertificatePassword,

        [Parameter()]
        [switch]$RetrievableAccounts,

        [Parameter()]
        [string]$Filter,

        [Parameter()]
        [bool]$ParseJson = $true
    )

    if (-not $Context) { $Context = Get-SgJTestContext }

    $toolArgs = "-a $($Context.Appliance) -x --retrievable-accounts -c `"$CertificateFile`""

    if ($CertificatePassword) {
        $toolArgs += " -p"
    }

    if ($Filter) {
        $toolArgs += " --filter `"$Filter`""
    }

    Write-Verbose "Invoke-SgJSafeguardA2a: $toolArgs"

    $stdinLine = if ($CertificatePassword) { $CertificatePassword } else { $null }
    return Invoke-SgJSafeguardTool -Arguments $toolArgs -StdinLine $stdinLine -ParseJson $ParseJson
}

function Test-SgJSpsConfigured {
    <#
    .SYNOPSIS
        Returns $true if SPS appliance parameters are configured in the test context.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [PSCustomObject]$Context
    )

    if (-not $Context) { $Context = Get-SgJTestContext }

    return (-not [string]::IsNullOrEmpty($Context.SpsAppliance) -and
            -not [string]::IsNullOrEmpty($Context.SpsUserName) -and
            -not [string]::IsNullOrEmpty($Context.SpsPassword))
}

function Test-SgJCertsConfigured {
    <#
    .SYNOPSIS
        Returns $true if test certificate files are present.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [PSCustomObject]$Context
    )

    if (-not $Context) { $Context = Get-SgJTestContext }

    return ((Test-Path $Context.UserPfx) -and
            (Test-Path $Context.RootCert) -and
            (Test-Path $Context.CaCert))
}

# ============================================================================
# Object Management
# ============================================================================

function Remove-SgJStaleTestObject {
    <#
    .SYNOPSIS
        Removes a test object by name from a collection, if it exists.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Context,

        [Parameter(Mandatory)]
        [string]$Collection,

        [Parameter(Mandatory)]
        [string]$Name
    )

    try {
        $items = Invoke-SgJSafeguardApi -Context $Context -Service Core -Method Get `
            -RelativeUrl "${Collection}?filter=Name eq '${Name}'"
        $itemList = @($items)
        foreach ($item in $itemList) {
            if ($item.Name -eq $Name) {
                Write-Host "    Removing stale $Collection object: $Name (Id=$($item.Id))" -ForegroundColor DarkYellow
                Invoke-SgJSafeguardApi -Context $Context -Service Core -Method Delete `
                    -RelativeUrl "${Collection}/$($item.Id)" -ParseJson $false
            }
        }
    }
    catch {
        Write-Verbose "Pre-cleanup of $Collection/$Name skipped: $($_.Exception.Message)"
    }
}

function Remove-SgJSafeguardTestObject {
    <#
    .SYNOPSIS
        Removes a Safeguard object by its direct URL.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Context,

        [Parameter(Mandatory)]
        [string]$RelativeUrl,

        [Parameter()]
        [string]$Username,

        [Parameter()]
        [string]$Password
    )

    $params = @{
        Context     = $Context
        Service     = "Core"
        Method      = "Delete"
        RelativeUrl = $RelativeUrl
        ParseJson   = $false
    }
    if ($Username) { $params["Username"] = $Username }
    if ($Password) { $params["Password"] = $Password }

    try {
        Invoke-SgJSafeguardApi @params
    }
    catch {
        Write-Verbose "Cleanup of $RelativeUrl skipped: $($_.Exception.Message)"
    }
}

function Remove-SgJStaleTestCert {
    <#
    .SYNOPSIS
        Removes a trusted certificate by thumbprint, if it exists.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Context,

        [Parameter(Mandatory)]
        [string]$Thumbprint
    )

    try {
        $certs = Invoke-SgJSafeguardApi -Context $Context -Service Core -Method Get `
            -RelativeUrl "TrustedCertificates?filter=Thumbprint ieq '$Thumbprint'"
        $certList = @($certs)
        foreach ($cert in $certList) {
            if ($cert.Thumbprint -and $cert.Thumbprint -ieq $Thumbprint) {
                Write-Host "    Removing stale trusted cert: $Thumbprint (Id=$($cert.Id))" -ForegroundColor DarkYellow
                Invoke-SgJSafeguardApi -Context $Context -Service Core -Method Delete `
                    -RelativeUrl "TrustedCertificates/$($cert.Id)" -ParseJson $false
            }
        }
    }
    catch {
        Write-Verbose "Pre-cleanup of cert $Thumbprint skipped: $($_.Exception.Message)"
    }
}

function Clear-SgJStaleTestEnvironment {
    <#
    .SYNOPSIS
        Removes all objects with the test prefix from previous runs.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Context
    )

    $prefix = $Context.TestPrefix
    foreach ($collection in @("AssetAccounts", "Assets", "Users")) {
        try {
            $items = Invoke-SgJSafeguardApi -Context $Context -Service Core -Method Get `
                -RelativeUrl "${collection}?filter=Name contains '${prefix}'"
            $itemList = @($items)
            foreach ($item in $itemList) {
                Write-Host "    Removing stale: $collection/$($item.Name) (Id=$($item.Id))" -ForegroundColor DarkYellow
                try {
                    Invoke-SgJSafeguardApi -Context $Context -Service Core -Method Delete `
                        -RelativeUrl "${collection}/$($item.Id)" -ParseJson $false
                }
                catch {
                    Write-Verbose "  Failed to remove $collection/$($item.Id): $($_.Exception.Message)"
                }
            }
        }
        catch {
            Write-Verbose "Pre-cleanup of $collection skipped: $($_.Exception.Message)"
        }
    }
}

# ============================================================================
# Assertion Functions
# ============================================================================

function Test-SgJAssert {
    <#
    .SYNOPSIS
        Runs a test assertion with continue-on-failure semantics.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]$Name,

        [Parameter(Mandatory, Position = 1)]
        [scriptblock]$Test
    )

    $ctx = Get-SgJTestContext
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $result = & $Test
        $sw.Stop()
        if ($result) {
            Write-Host "    PASS  $Name" -ForegroundColor Green
            $ctx.SuiteResults[-1].Assertions.Add([PSCustomObject]@{
                Name     = $Name
                Status   = "Pass"
                Duration = $sw.Elapsed.TotalSeconds
                Error    = $null
            })
        }
        else {
            Write-Host "    FAIL  $Name" -ForegroundColor Red
            $ctx.SuiteResults[-1].Assertions.Add([PSCustomObject]@{
                Name     = $Name
                Status   = "Fail"
                Duration = $sw.Elapsed.TotalSeconds
                Error    = "Assertion returned false"
            })
        }
    }
    catch {
        $sw.Stop()
        Write-Host "    FAIL  $Name" -ForegroundColor Red
        Write-Host "          $($_.Exception.Message)" -ForegroundColor DarkRed
        $ctx.SuiteResults[-1].Assertions.Add([PSCustomObject]@{
            Name     = $Name
            Status   = "Fail"
            Duration = $sw.Elapsed.TotalSeconds
            Error    = $_.Exception.Message
        })
    }
}

function Test-SgJAssertEqual {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]$Name,

        [Parameter(Mandatory, Position = 1)]
        $Expected,

        [Parameter(Mandatory, Position = 2)]
        $Actual
    )

    Test-SgJAssert $Name {
        if ($Expected -ne $Actual) {
            throw "Expected '$Expected' but got '$Actual'"
        }
        $true
    }
}

function Test-SgJAssertNotNull {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]$Name,

        [Parameter(Position = 1)]
        $Value
    )

    Test-SgJAssert $Name {
        if ($null -eq $Value) {
            throw "Expected non-null value"
        }
        $true
    }
}

function Test-SgJAssertContains {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]$Name,

        [Parameter(Mandatory, Position = 1)]
        [string]$Haystack,

        [Parameter(Mandatory, Position = 2)]
        [string]$Needle
    )

    Test-SgJAssert $Name {
        if (-not $Haystack.Contains($Needle)) {
            throw "String does not contain '$Needle'"
        }
        $true
    }
}

function Test-SgJAssertThrows {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]$Name,

        [Parameter(Mandatory, Position = 1)]
        [scriptblock]$Test
    )

    $ctx = Get-SgJTestContext
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        & $Test
        $sw.Stop()
        Write-Host "    FAIL  $Name (expected exception, none thrown)" -ForegroundColor Red
        $ctx.SuiteResults[-1].Assertions.Add([PSCustomObject]@{
            Name     = $Name
            Status   = "Fail"
            Duration = $sw.Elapsed.TotalSeconds
            Error    = "Expected exception but none was thrown"
        })
    }
    catch {
        $sw.Stop()
        Write-Host "    PASS  $Name (threw: $($_.Exception.Message))" -ForegroundColor Green
        $ctx.SuiteResults[-1].Assertions.Add([PSCustomObject]@{
            Name     = $Name
            Status   = "Pass"
            Duration = $sw.Elapsed.TotalSeconds
            Error    = $null
        })
    }
}

function Test-SgJSkip {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]$Name,

        [Parameter(Mandatory, Position = 1)]
        [string]$Reason
    )

    $ctx = Get-SgJTestContext
    Write-Host "    SKIP  $Name ($Reason)" -ForegroundColor Yellow
    $ctx.SuiteResults[-1].Assertions.Add([PSCustomObject]@{
        Name     = $Name
        Status   = "Skip"
        Duration = 0
        Error    = $Reason
    })
}

# ============================================================================
# Suite Execution
# ============================================================================

function Invoke-SgJTestSuite {
    <#
    .SYNOPSIS
        Runs a single test suite file through the Setup → Execute → Cleanup lifecycle.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$SuiteFile,

        [Parameter(Mandatory)]
        [PSCustomObject]$Context
    )

    $def = & $SuiteFile
    $shortName = (Split-Path -Leaf $SuiteFile) -replace '^Suite-', '' -replace '\.ps1$', ''

    # Reset per-suite state
    $Context.SuiteData = @{}
    $Context.CleanupActions.Clear()

    # Create result entry
    $suiteResult = [PSCustomObject]@{
        Name       = $shortName
        FullName   = $def.Name
        Status     = "Running"
        StartTime  = [DateTime]::UtcNow
        Duration   = 0
        Assertions = [System.Collections.Generic.List[PSCustomObject]]::new()
        SetupError = $null
    }
    $Context.SuiteResults.Add($suiteResult)

    Write-Host ""
    Write-Host ("─" * 60) -ForegroundColor DarkGray
    Write-Host "  Suite: $($def.Name)" -ForegroundColor Cyan
    if ($def.Description) {
        Write-Host "  $($def.Description)" -ForegroundColor DarkGray
    }
    Write-Host ("─" * 60) -ForegroundColor DarkGray

    $sw = [System.Diagnostics.Stopwatch]::StartNew()

    # --- Setup ---
    Write-Host "  Setup..." -ForegroundColor Yellow
    try {
        & $def.Setup $Context
        Write-Host "  Setup complete." -ForegroundColor Green
    }
    catch {
        $sw.Stop()
        $suiteResult.SetupError = $_.Exception.Message
        $suiteResult.Status = "SetupFailed"
        $suiteResult.Duration = $sw.Elapsed.TotalSeconds
        Write-Host "  Setup FAILED: $($_.Exception.Message)" -ForegroundColor Red
        # Still run cleanup
        Write-Host "  Cleanup (after setup failure)..." -ForegroundColor Yellow
        Invoke-SgJTestCleanup -Context $Context
        return
    }

    # --- Execute ---
    Write-Host "  Execute..." -ForegroundColor Yellow
    try {
        & $def.Execute $Context
    }
    catch {
        Write-Host "  Execute phase error: $($_.Exception.Message)" -ForegroundColor Red
    }

    # --- Cleanup ---
    Write-Host "  Cleanup..." -ForegroundColor Yellow
    try {
        & $def.Cleanup $Context
    }
    catch {
        Write-Host "  Suite cleanup error: $($_.Exception.Message)" -ForegroundColor DarkYellow
    }
    Invoke-SgJTestCleanup -Context $Context

    $sw.Stop()
    $suiteResult.Duration = $sw.Elapsed.TotalSeconds

    # Determine suite status
    $fails = @($suiteResult.Assertions | Where-Object { $_.Status -eq "Fail" })
    $suiteResult.Status = if ($fails.Count -gt 0) { "Failed" } else { "Passed" }
}

# ============================================================================
# Reporting
# ============================================================================

function Write-SgJTestReport {
    <#
    .SYNOPSIS
        Writes a summary report to the console and returns the failure count.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Context
    )

    $totalPass = 0
    $totalFail = 0
    $totalSkip = 0
    $totalSetupFail = 0

    Write-Host ""
    Write-Host ("=" * 66) -ForegroundColor Cyan
    Write-Host "  Test Results" -ForegroundColor Cyan
    Write-Host ("=" * 66) -ForegroundColor Cyan

    foreach ($suite in $Context.SuiteResults) {
        if ($suite.Status -eq "SetupFailed") {
            $totalSetupFail++
            Write-Host "  SETUP FAIL  $($suite.FullName) ($([math]::Round($suite.Duration, 1))s)" -ForegroundColor Red
            Write-Host "              $($suite.SetupError)" -ForegroundColor DarkRed
            continue
        }

        $pass = @($suite.Assertions | Where-Object { $_.Status -eq "Pass" }).Count
        $fail = @($suite.Assertions | Where-Object { $_.Status -eq "Fail" }).Count
        $skip = @($suite.Assertions | Where-Object { $_.Status -eq "Skip" }).Count
        $totalPass += $pass
        $totalFail += $fail
        $totalSkip += $skip

        $color = if ($fail -gt 0) { "Red" } else { "Green" }
        $status = if ($fail -gt 0) { "FAIL" } else { "PASS" }
        Write-Host "  $status  $($suite.FullName): $pass passed, $fail failed, $skip skipped ($([math]::Round($suite.Duration, 1))s)" -ForegroundColor $color
    }

    Write-Host ("─" * 66) -ForegroundColor DarkGray
    $totalDuration = [math]::Round(([DateTime]::UtcNow - $Context.StartTime).TotalSeconds, 1)
    Write-Host "  Total: $totalPass passed, $totalFail failed, $totalSkip skipped, $totalSetupFail setup failures ($totalDuration`s)" -ForegroundColor White
    Write-Host ("=" * 66) -ForegroundColor Cyan

    return $totalFail + $totalSetupFail
}

function Export-SgJTestReport {
    <#
    .SYNOPSIS
        Exports test results to a JSON file.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$OutputPath,

        [Parameter(Mandatory)]
        [PSCustomObject]$Context
    )

    $report = @{
        Appliance = $Context.Appliance
        StartTime = $Context.StartTime.ToString("o")
        EndTime   = [DateTime]::UtcNow.ToString("o")
        Suites    = @($Context.SuiteResults | ForEach-Object {
            @{
                Name       = $_.Name
                FullName   = $_.FullName
                Status     = $_.Status
                Duration   = $_.Duration
                SetupError = $_.SetupError
                Assertions = @($_.Assertions | ForEach-Object {
                    @{
                        Name     = $_.Name
                        Status   = $_.Status
                        Duration = $_.Duration
                        Error    = $_.Error
                    }
                })
            }
        })
    }

    $report | ConvertTo-Json -Depth 10 | Set-Content -Path $OutputPath -Encoding UTF8
    Write-Host "  Report exported to: $OutputPath" -ForegroundColor Green
}

# ============================================================================
# Build
# ============================================================================

function Build-SgJTestProjects {
    <#
    .SYNOPSIS
        Builds the SDK and test tool.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Context
    )

    $mvn = $Context.MavenCmd

    # Install SDK to local repo
    Write-Host "  Building SDK..." -ForegroundColor DarkGray
    $result = & $mvn -f "$($Context.RepoRoot)/pom.xml" install -DskipTests -q 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "SDK build failed: $result"
    }

    # Build and package the test tool
    Write-Host "  Building test tool..." -ForegroundColor DarkGray
    $result = & $mvn -f "$($Context.ToolDir)/pom.xml" clean package -q 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Test tool build failed: $result"
    }
}

# ============================================================================
# Exports
# ============================================================================

Export-ModuleMember -Function @(
    # Context
    'New-SgJTestContext'
    'Get-SgJTestContext'

    # Cleanup
    'Register-SgJTestCleanup'
    'Invoke-SgJTestCleanup'

    # Tool invocation
    'Invoke-SgJSafeguardTool'
    'Invoke-SgJSafeguardApi'
    'Invoke-SgJTokenCommand'
    'Invoke-SgJSafeguardSessions'
    'Test-SgJSpsConfigured'
    'Test-SgJCertsConfigured'

    # Object management
    'Remove-SgJStaleTestObject'
    'Remove-SgJSafeguardTestObject'
    'Remove-SgJStaleTestCert'
    'Clear-SgJStaleTestEnvironment'

    # Assertions
    'Test-SgJAssert'
    'Test-SgJAssertEqual'
    'Test-SgJAssertNotNull'
    'Test-SgJAssertContains'
    'Test-SgJAssertThrows'
    'Test-SgJSkip'

    # Suite execution
    'Invoke-SgJTestSuite'

    # Reporting
    'Write-SgJTestReport'
    'Export-SgJTestReport'

    # Build
    'Build-SgJTestProjects'
)

@{
    Name        = "Device Code Authentication"
    Description = "Tests the OAuth 2.0 Device Authorization Grant (Device Code) flow against a live appliance"
    Tags        = @("auth", "devicecode")

    Setup = {
        param($Context)

        if ([string]::IsNullOrEmpty($Context.Appliance) -or [string]::IsNullOrEmpty($Context.AdminPassword)) {
            return
        }

        # Capture the current Allowed OAuth2 Grant Types so the suite can toggle DeviceCode
        # and restore the original value during cleanup.
        $settings = Invoke-SgJSafeguardApi -Context $Context `
            -Service Core -Method Get -RelativeUrl "Settings" -Pkce
        $grant = $settings | Where-Object { $_.Name -eq "Allowed OAuth2 Grant Types" } | Select-Object -First 1
        $originalValue = if ($grant) { [string]$grant.Value } else { "" }

        $Context.SuiteData.OriginalGrantValue = $originalValue
        $Context.SuiteData.OriginalGrantTypes = @(
            $originalValue -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" }
        )

        Register-SgJTestCleanup -Description "Restore Allowed OAuth2 Grant Types" -Action {
            param($Context)
            Invoke-SgJSafeguardApi -Context $Context `
                -Service Core -Method Put -RelativeUrl "Settings/Allowed%20OAuth2%20Grant%20Types" `
                -Body @{ Name = "Allowed OAuth2 Grant Types"; Value = $Context.SuiteData.OriginalGrantValue } -Pkce | Out-Null
        }
    }

    Execute = {
        param($Context)

        if ([string]::IsNullOrEmpty($Context.Appliance) -or [string]::IsNullOrEmpty($Context.AdminPassword)) {
            Test-SgJSkip "Device Code authentication" "Appliance/admin credentials not configured"
            return
        }

        $deviceCodeArgs = "-a $($Context.Appliance) -x --device-code"

        # Helper to write the Allowed OAuth2 Grant Types setting.
        $setGrantTypes = {
            param($Context, [string[]]$Types)
            $value = ($Types -join ", ")
            Invoke-SgJSafeguardApi -Context $Context `
                -Service Core -Method Put -RelativeUrl "Settings/Allowed%20OAuth2%20Grant%20Types" `
                -Body @{ Name = "Allowed OAuth2 Grant Types"; Value = $value } -Pkce | Out-Null
        }

        # --- Disabled grant: DeviceCode removed from the allowed grant types ---
        $withoutDeviceCode = @($Context.SuiteData.OriginalGrantTypes | Where-Object { $_ -ne "DeviceCode" })
        if ($withoutDeviceCode.Count -eq 0) { $withoutDeviceCode = @("ResourceOwner") }
        & $setGrantTypes $Context $withoutDeviceCode

        Test-SgJAssertThrows "Device Code with grant disabled is rejected" {
            Invoke-SgJSafeguardTool -Arguments $deviceCodeArgs -ParseJson $false | Out-Null
        }

        Test-SgJAssert "Device Code disabled error instructs to enable the grant" {
            $message = $null
            try {
                Invoke-SgJSafeguardTool -Arguments $deviceCodeArgs -ParseJson $false | Out-Null
            }
            catch {
                $message = $_.Exception.Message
            }
            $null -ne $message -and ($message -match "(?i)grant type")
        }

        # --- Enabled grant: DeviceCode present in the allowed grant types ---
        $withDeviceCode = @($Context.SuiteData.OriginalGrantTypes)
        if ($withDeviceCode -notcontains "DeviceCode") { $withDeviceCode += "DeviceCode" }
        & $setGrantTypes $Context $withDeviceCode

        Test-SgJAssert "Device Code enabled flow returns a verification URL and user code" {
            $result = Invoke-SgJSafeguardTool -Arguments $deviceCodeArgs -ParseJson $true
            $display = $result.DeviceCodeDisplay
            $null -ne $display `
                -and -not [string]::IsNullOrEmpty([string]$display.VerificationUri) `
                -and -not [string]::IsNullOrEmpty([string]$display.UserCode)
        }
    }

    Cleanup = {
        param($Context)
        # Grant types are restored via the registered cleanup action.
    }
}

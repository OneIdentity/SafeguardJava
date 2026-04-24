@{
    Name        = "A2A Retrievable Accounts"
    Description = "Tests A2A retrievable account listing and SCIM filter support"
    Tags        = @("a2a", "certificate", "filter")

    Setup = {
        param($Context)

        if (-not (Test-SgJCertsConfigured -Context $Context)) {
            $Context.SuiteData["Skipped"] = $true
            return
        }

        $prefix = $Context.TestPrefix
        $accountName = "${prefix}_A2aAccount"
        $assetName = "${prefix}_A2aAsset"
        $regName = "${prefix}_A2aReg"
        $adminUser = "${prefix}_A2aAdmin"
        $adminPassword = "Test1234A2aAdmin!@#"

        # Compute thumbprints
        Write-Host "    Computing certificate thumbprints..." -ForegroundColor DarkGray
        $userThumbprint = (New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
            $Context.UserPfx, "a")).Thumbprint
        $rootThumbprint = (New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
            $Context.RootCert)).Thumbprint
        $caThumbprint = (New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
            $Context.CaCert)).Thumbprint

        $Context.SuiteData["UserThumbprint"] = $userThumbprint
        $Context.SuiteData["AccountName"]    = $accountName

        # Pre-cleanup: remove stale objects in reverse dependency order
        Write-Host "    Removing stale objects from previous runs..." -ForegroundColor DarkGray
        Remove-SgJStaleTestObject -Context $Context -Collection "A2ARegistrations" -Name $regName
        Remove-SgJStaleTestObject -Context $Context -Collection "AssetAccounts" -Name $accountName
        Remove-SgJStaleTestObject -Context $Context -Collection "Assets" -Name $assetName
        Remove-SgJStaleTestObject -Context $Context -Collection "Users" -Name "${prefix}_A2aCertUser"
        Remove-SgJStaleTestObject -Context $Context -Collection "Users" -Name $adminUser
        Remove-SgJStaleTestCert -Context $Context -Thumbprint $caThumbprint
        Remove-SgJStaleTestCert -Context $Context -Thumbprint $rootThumbprint

        # 1. Create admin user with AssetAdmin role for privileged operations
        Write-Host "    Creating admin user '$adminUser'..." -ForegroundColor DarkGray
        $admin = Invoke-SgJSafeguardApi -Context $Context -Service Core -Method Post `
            -RelativeUrl "Users" -Body @{
                PrimaryAuthenticationProvider = @{ Id = -1 }
                Name = $adminUser
                AdminRoles = @('GlobalAdmin','Auditor','AssetAdmin','ApplianceAdmin','PolicyAdmin','UserAdmin','HelpdeskAdmin','OperationsAdmin')
            }
        $Context.SuiteData["AdminUserId"] = $admin.Id
        $Context.SuiteData["AdminUser"] = $adminUser
        $Context.SuiteData["AdminPassword"] = $adminPassword
        Register-SgJTestCleanup -Description "Delete A2A admin user" -Action {
            param($Ctx)
            Remove-SgJSafeguardTestObject -Context $Ctx `
                -RelativeUrl "Users/$($Ctx.SuiteData['AdminUserId'])"
        }
        Invoke-SgJSafeguardApi -Context $Context -Service Core -Method Put `
            -RelativeUrl "Users/$($admin.Id)/Password" -Body "'$adminPassword'" -ParseJson $false

        # 2. Check and save current A2A service state for restore in cleanup
        Write-Host "    Checking A2A service state..." -ForegroundColor DarkGray
        try {
            $a2aStatus = Invoke-SgJSafeguardApi -Context $Context -Service Appliance -Method Get `
                -RelativeUrl "A2AService/Status"
            $Context.SuiteData["A2aWasEnabled"] = ($a2aStatus -and $a2aStatus.IsEnabled -eq $true)
        }
        catch {
            $Context.SuiteData["A2aWasEnabled"] = $false
        }

        # 3. Upload Root CA as trusted certificate
        Write-Host "    Uploading Root CA..." -ForegroundColor DarkGray
        $rootCertData = [string](Get-Content -Raw $Context.RootCert)
        $rootCert = Invoke-SgJSafeguardApi -Context $Context -Service Core -Method Post `
            -RelativeUrl "TrustedCertificates" `
            -Username $adminUser -Password $adminPassword `
            -Body @{ Base64CertificateData = $rootCertData }
        $Context.SuiteData["RootCertId"] = $rootCert.Id
        Register-SgJTestCleanup -Description "Delete Root CA trust" -Action {
            param($Ctx)
            Remove-SgJSafeguardTestObject -Context $Ctx `
                -RelativeUrl "TrustedCertificates/$($Ctx.SuiteData['RootCertId'])" `
                -Username $Ctx.SuiteData['AdminUser'] -Password $Ctx.SuiteData['AdminPassword']
        }

        # 4. Upload Intermediate CA as trusted certificate
        Write-Host "    Uploading Intermediate CA..." -ForegroundColor DarkGray
        $caCertData = [string](Get-Content -Raw $Context.CaCert)
        $caCert = Invoke-SgJSafeguardApi -Context $Context -Service Core -Method Post `
            -RelativeUrl "TrustedCertificates" `
            -Username $adminUser -Password $adminPassword `
            -Body @{ Base64CertificateData = $caCertData }
        $Context.SuiteData["CaCertId"] = $caCert.Id
        Register-SgJTestCleanup -Description "Delete Intermediate CA trust" -Action {
            param($Ctx)
            Remove-SgJSafeguardTestObject -Context $Ctx `
                -RelativeUrl "TrustedCertificates/$($Ctx.SuiteData['CaCertId'])" `
                -Username $Ctx.SuiteData['AdminUser'] -Password $Ctx.SuiteData['AdminPassword']
        }

        # 5. Create certificate user mapped to user cert thumbprint
        Write-Host "    Creating certificate user..." -ForegroundColor DarkGray
        $certUser = "${prefix}_A2aCertUser"
        $cUser = Invoke-SgJSafeguardApi -Context $Context -Service Core -Method Post `
            -RelativeUrl "Users" `
            -Username $adminUser -Password $adminPassword `
            -Body @{
                PrimaryAuthenticationProvider = @{
                    Id = -2
                    Identity = $userThumbprint
                }
                Name = $certUser
            }
        $Context.SuiteData["CertUserId"] = $cUser.Id
        Register-SgJTestCleanup -Description "Delete A2A certificate user" -Action {
            param($Ctx)
            Remove-SgJSafeguardTestObject -Context $Ctx `
                -RelativeUrl "Users/$($Ctx.SuiteData['CertUserId'])" `
                -Username $Ctx.SuiteData['AdminUser'] -Password $Ctx.SuiteData['AdminPassword']
        }

        # 6. Create test asset
        Write-Host "    Creating asset '$assetName'..." -ForegroundColor DarkGray
        $asset = Invoke-SgJSafeguardApi -Context $Context -Service Core -Method Post `
            -RelativeUrl "Assets" `
            -Username $adminUser -Password $adminPassword `
            -Body @{
                Name = $assetName
                Description = "Test asset for A2A retrievable accounts"
                PlatformId = 188
                AssetPartitionId = -1
                NetworkAddress = "fake.a2a.test.address.com"
            }
        $Context.SuiteData["AssetId"] = $asset.Id
        Register-SgJTestCleanup -Description "Delete test asset" -Action {
            param($Ctx)
            Remove-SgJSafeguardTestObject -Context $Ctx `
                -RelativeUrl "Assets/$($Ctx.SuiteData['AssetId'])" `
                -Username $Ctx.SuiteData['AdminUser'] -Password $Ctx.SuiteData['AdminPassword']
        }

        # 7. Create asset account
        Write-Host "    Creating account '$accountName'..." -ForegroundColor DarkGray
        $account = Invoke-SgJSafeguardApi -Context $Context -Service Core -Method Post `
            -RelativeUrl "AssetAccounts" `
            -Username $adminUser -Password $adminPassword `
            -Body @{
                Name = $accountName
                Asset = @{ Id = $asset.Id }
            }
        $Context.SuiteData["AccountId"] = $account.Id
        Register-SgJTestCleanup -Description "Delete asset account" -Action {
            param($Ctx)
            Remove-SgJSafeguardTestObject -Context $Ctx `
                -RelativeUrl "AssetAccounts/$($Ctx.SuiteData['AccountId'])" `
                -Username $Ctx.SuiteData['AdminUser'] -Password $Ctx.SuiteData['AdminPassword']
        }

        # 8. Set account password
        Write-Host "    Setting account password..." -ForegroundColor DarkGray
        Invoke-SgJSafeguardApi -Context $Context -Service Core -Method Put `
            -RelativeUrl "AssetAccounts/$($account.Id)/Password" `
            -Username $adminUser -Password $adminPassword `
            -Body "'TestA2aPassword123!'" -ParseJson $false
        $Context.SuiteData["AccountPassword"] = "TestA2aPassword123!"

        # 9. Create A2A registration linked to certificate user
        Write-Host "    Creating A2A registration '$regName'..." -ForegroundColor DarkGray
        $a2aReg = Invoke-SgJSafeguardApi -Context $Context -Service Core -Method Post `
            -RelativeUrl "A2ARegistrations" `
            -Username $adminUser -Password $adminPassword `
            -Body @{
                AppName = $regName
                VisibleToCertificateUsers = $true
                BidirectionalEnabled = $true
                Description = "Test A2A registration for SafeguardJava"
                CertificateUserId = $cUser.Id
            }
        $Context.SuiteData["A2aRegId"] = $a2aReg.Id
        Register-SgJTestCleanup -Description "Delete A2A registration" -Action {
            param($Ctx)
            Remove-SgJSafeguardTestObject -Context $Ctx `
                -RelativeUrl "A2ARegistrations/$($Ctx.SuiteData['A2aRegId'])" `
                -Username $Ctx.SuiteData['AdminUser'] -Password $Ctx.SuiteData['AdminPassword']
        }

        # 10. Add retrievable account to A2A registration
        Write-Host "    Adding retrievable account to A2A registration..." -ForegroundColor DarkGray
        $retrievable = Invoke-SgJSafeguardApi -Context $Context -Service Core -Method Post `
            -RelativeUrl "A2ARegistrations/$($a2aReg.Id)/RetrievableAccounts" `
            -Username $adminUser -Password $adminPassword `
            -Body @{ AccountId = $account.Id }
        $Context.SuiteData["ApiKey"] = $retrievable.ApiKey

        # 11. Enable A2A service
        Write-Host "    Enabling A2A service..." -ForegroundColor DarkGray
        Invoke-SgJSafeguardApi -Context $Context -Service Appliance -Method Post `
            -RelativeUrl "A2AService/Enable" -ParseJson $false
        Register-SgJTestCleanup -Description "Restore A2A service state" -Action {
            param($Ctx)
            if (-not $Ctx.SuiteData['A2aWasEnabled']) {
                try {
                    Invoke-SgJSafeguardApi -Context $Ctx -Service Appliance -Method Post `
                        -RelativeUrl "A2AService/Disable" -ParseJson $false
                }
                catch {
                    Write-Verbose "Failed to disable A2A service: $($_.Exception.Message)"
                }
            }
        }

        # Brief pause for service readiness
        Start-Sleep -Seconds 2
    }

    Execute = {
        param($Context)

        if ($Context.SuiteData["Skipped"]) {
            Test-SgJSkip "A2A list retrievable accounts" "Test certificates not found"
            Test-SgJSkip "Retrievable account has expected AccountName" "Test certificates not found"
            Test-SgJSkip "Filter by matching AccountName returns results" "Test certificates not found"
            Test-SgJSkip "Filter with no matches returns empty list" "Test certificates not found"
            Test-SgJSkip "Invalid filter property gives useful error" "Test certificates not found"
            Test-SgJSkip "Malformed filter expression gives useful error" "Test certificates not found"
            Test-SgJSkip "A2A retrieve password via PFX" "Test certificates not found"
            Test-SgJSkip "A2A set password via PFX and verify" "Test certificates not found"
            Test-SgJSkip "A2A retrieve password with bad API key fails" "Test certificates not found"
            return
        }

        $accountName = $Context.SuiteData["AccountName"]
        $accountId = $Context.SuiteData["AccountId"]
        $apiKey = $Context.SuiteData["ApiKey"]
        $originalPassword = $Context.SuiteData["AccountPassword"]

        # --- Unfiltered listing ---

        Test-SgJAssert "A2A list retrievable accounts" {
            $result = Invoke-SgJSafeguardA2a -Context $Context `
                -CertificateFile $Context.UserPfx -CertificatePassword "a"
            $accounts = @($result)
            $match = $accounts | Where-Object { $_.AccountId -eq $accountId }
            $null -ne $match
        }

        Test-SgJAssert "Retrievable account has expected AccountName" {
            $result = Invoke-SgJSafeguardA2a -Context $Context `
                -CertificateFile $Context.UserPfx -CertificatePassword "a"
            $accounts = @($result)
            $match = $accounts | Where-Object { $_.AccountId -eq $accountId }
            $match.AccountName -eq $accountName
        }

        # --- Filtered listing ---

        Test-SgJAssert "Filter by matching AccountName returns results" {
            $result = Invoke-SgJSafeguardA2a -Context $Context `
                -CertificateFile $Context.UserPfx -CertificatePassword "a" `
                -Filter "AccountName eq '$accountName'"
            $accounts = @($result)
            $match = $accounts | Where-Object { $_.AccountId -eq $accountId }
            $null -ne $match
        }

        Test-SgJAssert "Filter with no matches returns empty list" {
            $raw = Invoke-SgJSafeguardA2a -Context $Context `
                -CertificateFile $Context.UserPfx -CertificatePassword "a" `
                -Filter "AccountName eq 'NonExistentAccount_xyz_999'" `
                -ParseJson $false
            $raw -match '\[\s*\]'
        }

        # --- Error handling ---

        Test-SgJAssert "Invalid filter property gives useful error" {
            $threw = $false
            try {
                Invoke-SgJSafeguardA2a -Context $Context `
                    -CertificateFile $Context.UserPfx -CertificatePassword "a" `
                    -Filter "This eq 'broken'"
            }
            catch {
                $threw = ($_.Exception.Message -match "invalid filter" -or
                          $_.Exception.Message -match "not a valid filter" -or
                          $_.Exception.Message -match "BadRequest" -or
                          $_.Exception.Message -match "400")
            }
            $threw
        }

        Test-SgJAssert "Malformed filter expression gives useful error" {
            $threw = $false
            try {
                Invoke-SgJSafeguardA2a -Context $Context `
                    -CertificateFile $Context.UserPfx -CertificatePassword "a" `
                    -Filter "not even close to a filter!!!"
            }
            catch {
                $threw = ($_.Exception.Message -match "invalid filter" -or
                          $_.Exception.Message -match "not a valid filter" -or
                          $_.Exception.Message -match "error" -or
                          $_.Exception.Message -match "BadRequest" -or
                          $_.Exception.Message -match "400")
            }
            $threw
        }

        # --- Credential retrieval ---

        Test-SgJAssert "A2A retrieve password via PFX" {
            $result = Invoke-SgJSafeguardA2a -Context $Context `
                -CertificateFile $Context.UserPfx -CertificatePassword "a" `
                -ApiKey $apiKey -RetrievePassword
            $result.Trim() -eq $originalPassword
        }

        Test-SgJAssert "A2A set password via PFX and verify" {
            $updatedPassword = "UpdatedA2aPass456!@#"
            Invoke-SgJSafeguardA2a -Context $Context `
                -CertificateFile $Context.UserPfx -CertificatePassword "a" `
                -ApiKey $apiKey -SetPassword -NewPassword $updatedPassword
            $retrieved = Invoke-SgJSafeguardA2a -Context $Context `
                -CertificateFile $Context.UserPfx -CertificatePassword "a" `
                -ApiKey $apiKey -RetrievePassword
            $retrieved.Trim() -eq $updatedPassword
        }

        Test-SgJAssert "A2A retrieve password with bad API key fails" {
            $threw = $false
            try {
                Invoke-SgJSafeguardA2a -Context $Context `
                    -CertificateFile $Context.UserPfx -CertificatePassword "a" `
                    -ApiKey "00000000-0000-0000-0000-000000000000" -RetrievePassword
            }
            catch {
                $threw = ($_.Exception.Message -match "404" -or
                          $_.Exception.Message -match "NotFound" -or
                          $_.Exception.Message -match "not found" -or
                          $_.Exception.Message -match "403" -or
                          $_.Exception.Message -match "Forbidden" -or
                          $_.Exception.Message -match "Error")
            }
            $threw
        }
    }

    Cleanup = {
        param($Context)
        # Registered cleanup handles everything.
    }
}

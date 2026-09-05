@{
    Name        = "Certificate Authentication"
    Description = "Tests certificate-based authentication via PFX file"
    Tags        = @("auth", "certificate")

    Setup = {
        param($Context)

        if (-not (Test-SgJCertsConfigured -Context $Context)) {
            $Context.SuiteData["Skipped"] = $true
            return
        }

        $prefix = $Context.TestPrefix
        $certUser = "${prefix}_CertUser"

        # Compute thumbprints using .NET X509Certificate2
        $userThumbprint = (New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
            $Context.UserPfx, "a")).Thumbprint
        $rootThumbprint = (New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
            $Context.RootCert)).Thumbprint
        $caThumbprint = (New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
            $Context.CaCert)).Thumbprint

        $Context.SuiteData["UserThumbprint"] = $userThumbprint
        $Context.SuiteData["RootThumbprint"] = $rootThumbprint
        $Context.SuiteData["CaThumbprint"]   = $caThumbprint
        $Context.SuiteData["CertUserName"]   = $certUser

        # Pre-cleanup: remove stale objects from previous failed runs
        Remove-SgJStaleTestObject -Context $Context -Collection "Users" -Name $certUser
        Remove-SgJStaleTestCert -Context $Context -Thumbprint $caThumbprint
        Remove-SgJStaleTestCert -Context $Context -Thumbprint $rootThumbprint

        # 1. Upload Root CA as trusted certificate
        $rootCertData = [string](Get-Content -Raw $Context.RootCert)
        $rootCert = Invoke-SgJSafeguardApi -Context $Context -Service Core -Method Post `
            -RelativeUrl "TrustedCertificates" `
            -Body @{ Base64CertificateData = $rootCertData }
        $Context.SuiteData["RootCertId"] = $rootCert.Id
        Register-SgJTestCleanup -Description "Delete Root CA trust" -Action {
            param($Ctx)
            Remove-SgJSafeguardTestObject -Context $Ctx `
                -RelativeUrl "TrustedCertificates/$($Ctx.SuiteData['RootCertId'])"
        }

        # 2. Upload Intermediate CA as trusted certificate
        $caCertData = [string](Get-Content -Raw $Context.CaCert)
        $caCert = Invoke-SgJSafeguardApi -Context $Context -Service Core -Method Post `
            -RelativeUrl "TrustedCertificates" `
            -Body @{ Base64CertificateData = $caCertData }
        $Context.SuiteData["CaCertId"] = $caCert.Id
        Register-SgJTestCleanup -Description "Delete Intermediate CA trust" -Action {
            param($Ctx)
            Remove-SgJSafeguardTestObject -Context $Ctx `
                -RelativeUrl "TrustedCertificates/$($Ctx.SuiteData['CaCertId'])"
        }

        # 3. Create certificate user mapped to user cert thumbprint
        $cUser = Invoke-SgJSafeguardApi -Context $Context -Service Core -Method Post `
            -RelativeUrl "Users" `
            -Body @{
                PrimaryAuthenticationProvider = @{
                    Id = -2
                    Identity = $userThumbprint
                }
                Name = $certUser
            }
        $Context.SuiteData["CertUserId"] = $cUser.Id
        Register-SgJTestCleanup -Description "Delete certificate user" -Action {
            param($Ctx)
            Remove-SgJSafeguardTestObject -Context $Ctx `
                -RelativeUrl "Users/$($Ctx.SuiteData['CertUserId'])"
        }
    }

    Execute = {
        param($Context)

        if ($Context.SuiteData["Skipped"]) {
            Test-SgJSkip "Auth as cert user from PFX file" "Test certificates not found"
            Test-SgJSkip "Cert user identity matches expected name" "Test certificates not found"
            Test-SgJSkip "Auth as cert user over TLS 1.3 (Cert SNI)" "Test certificates not found"
            return
        }

        Test-SgJAssert "Auth as cert user from PFX file" {
            $result = Invoke-SgJSafeguardApi -Context $Context `
                -Service Core -Method Get -RelativeUrl "Me" `
                -CertificateFile $Context.UserPfx -CertificatePassword "a"
            $null -ne $result
        }

        Test-SgJAssert "Cert user identity matches expected name" {
            $result = Invoke-SgJSafeguardApi -Context $Context `
                -Service Core -Method Get -RelativeUrl "Me" `
                -CertificateFile $Context.UserPfx -CertificatePassword "a"
            $result.Name -eq $Context.SuiteData["CertUserName"]
        }

        Test-SgJAssert "Cert auth Me response contains user Id" {
            $result = Invoke-SgJSafeguardApi -Context $Context `
                -Service Core -Method Get -RelativeUrl "Me" `
                -CertificateFile $Context.UserPfx -CertificatePassword "a"
            $result.Id -eq $Context.SuiteData["CertUserId"]
        }

        Test-SgJAssert "Cert auth full response has status 200" {
            $result = Invoke-SgJSafeguardApi -Context $Context `
                -Service Core -Method Get -RelativeUrl "Me" `
                -CertificateFile $Context.UserPfx -CertificatePassword "a" -Full
            $result.StatusCode -eq 200
        }

        # Certificate authentication over TLS 1.3. JSSE cannot present a client
        # certificate in response to a TLS 1.3 post-handshake CertificateRequest, so
        # cert auth over TLS 1.3 only succeeds against the appliance Cert SNI binding,
        # where the certificate is requested in-handshake. Requires an admin-configured
        # Cert SNI hostname; skipped unless -CertSniHost is supplied.
        if (-not $Context.CertSniHost) {
            Test-SgJSkip "Auth as cert user over TLS 1.3 (Cert SNI)" `
                "No -CertSniHost specified"
        }
        elseif (-not (Test-SgJApplianceTls13 -ApplianceHost $Context.CertSniHost)) {
            Test-SgJSkip "Auth as cert user over TLS 1.3 (Cert SNI)" `
                "Cert SNI host $($Context.CertSniHost) does not negotiate TLS 1.3"
        }
        else {
            Test-SgJAssert "Auth as cert user over TLS 1.3 (Cert SNI)" {
                $result = Invoke-SgJSafeguardApi -Context $Context `
                    -Service Core -Method Get -RelativeUrl "Me" `
                    -CertificateFile $Context.UserPfx -CertificatePassword "a" `
                    -ApplianceOverride $Context.CertSniHost -MinTlsVersion 1.3
                $null -ne $result -and $result.Name -eq $Context.SuiteData["CertUserName"]
            }
        }
    }

    Cleanup = {
        param($Context)
        # Registered cleanup handles everything.
    }
}

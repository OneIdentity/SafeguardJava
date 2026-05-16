---
name: testing-guide
description: >-
  Use when running tests, writing tests, investigating test failures,
  or setting up a test environment against a live Safeguard appliance.
  Covers the PowerShell test framework, CLI test tool, test suites,
  module-to-suite mapping, and writing new suites.
---

# Testing Guide

This SDK interacts with a live Safeguard appliance API. **There are no mock/unit tests.**
The `tests/` directory contains a CLI test tool and the `TestFramework/` directory contains
a PowerShell integration test framework. Running tests against a live appliance is the only
way to validate changes.

## Asking the user for appliance access

**If you are making non-trivial code changes, ask the user whether they have access to a
live Safeguard appliance for testing.** If they do, ask for:

1. **Appliance address** (IP or hostname of a Safeguard for Privileged Passwords appliance)
2. **Admin password** (for the built-in `admin` account — the bootstrap administrator)
3. *(Optional)* **SPS appliance address** (for Safeguard for Privileged Sessions tests)
4. *(Optional)* **SPS credentials** (username and password for the SPS appliance)

This is not required for documentation or minor fixes, but it is **strongly encouraged**
for any change that touches authentication, API calls, connection logic, event handling,
or streaming.

## Connecting to the appliance (PKCE vs Resource Owner Grant)

**Resource Owner Grant (ROG) is disabled by default** on Safeguard appliances. The SDK's
`PasswordAuthenticator` uses ROG under the hood, which will fail with a 400 error when ROG
is disabled.

The test framework handles this automatically — it checks whether ROG is enabled via a
preflight PKCE connection and enables it if needed. It also restores the original setting
when tests complete. You should not need to manually enable ROG.

If you are testing manually and receive a 400 error like
`"OAuth2 resource owner password credentials grant type is not allowed"`, you can either:
- Use PKCE authentication (`--pkce` flag in the test tool)
- Enable ROG via the appliance Settings API

## Running the PowerShell test suite

```powershell
# Build first (always build before testing)
mvn clean package "-Dspotbugs.skip=true"

# Run all suites
cd TestFramework
pwsh -File Invoke-SafeguardTests.ps1 `
    -Appliance <address> -AdminPassword <password>

# Run with SPS tests
pwsh -File Invoke-SafeguardTests.ps1 `
    -Appliance <address> -AdminPassword <password> `
    -SpsAppliance <sps-address> -SpsPassword <sps-password>

# Run a specific suite by name
pwsh -File Invoke-SafeguardTests.ps1 `
    -Appliance <address> -AdminPassword <password> `
    -Suite PasswordAuth

# List available suites
pwsh -File Invoke-SafeguardTests.ps1 -ListSuites
```

**Important:** The test runner requires **PowerShell 7** (`pwsh`). It:
- Builds the SDK and test tool automatically before running tests
- Validates the appliance is reachable (preflight HTTPS check)
- Checks and enables Resource Owner Grant if needed (via PKCE bootstrap)
- Discovers and runs suite files from `TestFramework/Suites/`
- Cleans up test objects and restores appliance settings when done
- Reports pass/fail/skip with structured output

## Current test suites

| Suite | Tests | What it covers |
|---|---|---|
| A2ARetrievableAccounts | 6 | A2A retrievable account listing and SCIM filter support (requires test certs) |
| AccessTokenAuth | 5 | Pre-obtained access token authentication |
| AnonymousAccess | 3 | Unauthenticated Notification service access |
| ApiInvocation | 12 | GET/POST/PUT/DELETE, filters, ordering, full responses |
| CertificateAuth | 4 | Certificate-based authentication via PFX file |
| PasswordAuth | 5 | Password authentication, negative tests |
| PkceAuth | 8 | PKCE authentication, token operations, negative tests |
| SpsIntegration | 4 | SPS connectivity (requires SPS appliance) |
| Streaming | 5 | Streaming upload/download via backup endpoints |
| TokenManagement | 8 | Token lifecycle: get, refresh, bounds, logout |

## Running the CLI test tool directly

The test tool is a standalone Java CLI in `tests/safeguardjavaclient/`:

```powershell
# Build the test tool
cd tests/safeguardjavaclient
mvn package "-Dspotbugs.skip=true" -q

# Find the built jar
$jar = Get-ChildItem target/*.jar | Select-Object -First 1

# Password auth — GET Me endpoint
echo '<password>' | java -jar $jar -a <appliance> -u admin -p -x -s Core -m Get -U Me

# PKCE auth — GET Me endpoint
echo '<password>' | java -jar $jar -a <appliance> -u admin -p -x -s Core -m Get -U Me --pkce

# Anonymous — GET Notification Status
java -jar $jar -a <appliance> -x -s Notification -m Get -U Status -A

# Access token auth (provide token directly)
java -jar $jar -a <appliance> -x -s Core -m Get -U Me -T <access-token>

# Full response (includes StatusCode, Headers, Body)
echo '<password>' | java -jar $jar -a <appliance> -u admin -p -x -s Core -m Get -U Me -F

# POST with body
echo '<password>' | java -jar $jar -a <appliance> -u admin -p -x -s Core -m Post -U Users -B '{"Name":"test"}'

# Token operations
echo '<password>' | java -jar $jar -a <appliance> -u admin -p -x --get-token
echo '<password>' | java -jar $jar -a <appliance> -u admin -p -x --token-lifetime
echo '<password>' | java -jar $jar -a <appliance> -u admin -p -x --refresh-token
echo '<password>' | java -jar $jar -a <appliance> -u admin -p -x --logout

# SPS connection
echo '<password>' | java -jar $jar --sps <sps-address> -u admin -p -x -s Core -m Get -U "/api/configuration/management/email"

# Streaming download
echo '<password>' | java -jar $jar -a <appliance> -u admin -p -x --download-stream Appliance/Backups/<id>

# Streaming upload
echo '<password>' | java -jar $jar -a <appliance> -u admin -p -x --upload-stream Appliance/Backups/Upload --upload-file backup.sgb

# A2A — list all retrievable accounts (certificate auth)
echo '<cert-password>' | java -jar $jar -a <appliance> -c <pfx-file> -p -x --retrievable-accounts

# A2A — list retrievable accounts with SCIM filter
echo '<cert-password>' | java -jar $jar -a <appliance> -c <pfx-file> -p -x --retrievable-accounts --filter "AccountName eq 'myaccount'"
```

## Module-to-suite mapping

When you change a specific SDK module, run the relevant suite(s) rather than the full set:

| SDK module | Relevant test suite(s) |
|---|---|
| `Safeguard.java` | PasswordAuth, CertificateAuth, AccessTokenAuth, AnonymousAccess |
| `SafeguardConnection.java` | ApiInvocation, TokenManagement |
| `PersistentSafeguardConnection.java` | TokenManagement |
| `authentication/PasswordAuthenticator.java` | PasswordAuth, PkceAuth |
| `authentication/CertificateAuthenticator.java` | CertificateAuth |
| `authentication/AccessTokenAuthenticator.java` | AccessTokenAuth |
| `authentication/AnonymousAuthenticator.java` | AnonymousAccess |
| `restclient/RestClient.java` | ApiInvocation, Streaming |
| `SafeguardForPrivilegedSessions.java` | SpsIntegration (requires SPS appliance) |
| `*Streaming*` classes | Streaming |
| `event/` classes | (no automated suite yet — test manually) |
| `SafeguardA2AContext.java` | A2ARetrievableAccounts (requires test certs) |

## Fixing test failures

When a test fails, **investigate and fix the source code first** — do not change the test
to make it pass without asking the user. The test suite exists to catch regressions.

Only modify a test if:
- The test itself has a genuine bug (wrong assertion logic, stale assumptions)
- The user explicitly approves changing the test
- A new feature intentionally changes behavior and the test needs updating

Always ask the user before weakening or removing an assertion.

## Troubleshooting

### ROG 400 errors

If you see `"OAuth2 resource owner password credentials grant type is not allowed"`:
- The test framework enables ROG automatically during test runs
- For ad-hoc manual testing, use `--pkce` flag instead of password auth
- To enable ROG manually: GET/PUT `/service/appliance/v4/Settings` and set
  `LoginConfiguration.ResourceOwnerGrantAllowed` to `true`

### SSL handshake failures

The CLI test tool uses `-x` to ignore SSL certificate validation. If you're
calling the SDK programmatically without `ignoreSsl=true`, ensure:
- The appliance certificate is trusted by the JVM's cacerts keystore, OR
- You're passing `ignoreSsl=true` for development/test environments

### Appliance unreachable

The test framework performs a preflight HTTPS check. If it fails:
- Verify the appliance IP/hostname is correct and reachable from this machine
- Check firewall rules — Safeguard uses port 443 (HTTPS)
- Try `curl -k https://<appliance>/service/notification/v4/Status` to verify

## Test data certificates

The `TestFramework/TestData/CERTS/` directory contains a simple PKI for testing
certificate authentication and A2A:

| File | Purpose |
|---|---|
| `RootCA.*` | Self-signed root CA |
| `IntermediateCA.*` | Intermediate CA signed by RootCA |
| `UserCert.*` | End-entity user certificate signed by IntermediateCA |

Each certificate is available in multiple formats: `.cer` (DER), `.pem`,
`.pfx` (PKCS#12), and `.pvk` (private key).

**The password for all certificates is: `a`**

To use these for A2A or certificate auth testing, the certificate chain must be
uploaded to the Safeguard appliance as a trusted certificate authority.

## Writing a new test suite

### Suite file structure

Create `TestFramework/Suites/Suite-YourFeature.ps1` returning a hashtable:

```powershell
@{
    Name        = "Your Feature"
    Description = "Tests for your feature"
    Tags        = @("yourfeature")

    Setup = {
        param($Context)
        # Create test objects, store in $Context.SuiteData
        # Register cleanup actions with Register-SgJTestCleanup
    }

    Execute = {
        param($Context)

        # Success test
        Test-SgJAssert "Can do the thing" {
            $result = Invoke-SgJSafeguardApi -Context $Context `
                -Service Core -Method Get -RelativeUrl "Me"
            $null -ne $result -and $result.Name -eq "expected"
        }

        # Error test
        Test-SgJAssertThrows "Rejects bad input" {
            Invoke-SgJSafeguardApi -Context $Context `
                -Service Core -Method Get -RelativeUrl "Me" `
                -Username "baduser" -Password "wrong"
        }
    }

    Cleanup = {
        param($Context)
        # Registered cleanup handles everything.
    }
}
```

### Key framework functions

| Function | Purpose |
|---|---|
| `Invoke-SgJSafeguardApi` | Call Safeguard API via the test tool. Supports `-Service`, `-Method`, `-RelativeUrl`, `-Body`, `-Full`, `-Anonymous`, `-Pkce`, `-Username`, `-Password`, `-AccessToken` |
| `Invoke-SgJSafeguardA2a` | List A2A retrievable accounts via certificate auth. Supports `-CertificateFile`, `-CertificatePassword`, `-Filter`, `-ParseJson` |
| `Invoke-SgJTokenCommand` | Token operations: `GetToken`, `TokenLifetime`, `RefreshToken`, `Logout` |
| `Test-SgJAssert` | Assert that a script block returns `$true` |
| `Test-SgJAssertThrows` | Assert that a script block throws an error |
| `Register-SgJTestCleanup` | Register a cleanup action (runs in LIFO order after suite) |
| `Remove-SgJStaleTestObject` | Pre-cleanup helper to remove leftover test objects |
| `Remove-SgJSafeguardTestObject` | Delete a specific object by relative URL |

### Test naming prefix

All test objects should use `$Context.TestPrefix` (default: `SgJTest`) to avoid collisions:

```powershell
$userName = "$($Context.TestPrefix)_MyTestUser"
```

### Test validation guidelines

Write tests with **strong validation criteria**:
- Check specific field values, not just "not null"
- Validate HTTP status codes (200, 201, 204) on full responses
- Include negative tests (wrong password, invalid token, bad endpoints)
- Verify bounds on numeric values (e.g., token lifetime 1-1440 minutes)
- Match user identities to confirm correct authentication

### Adding test tool commands

If a test requires functionality not exposed by the CLI test tool:

1. Add the CLI option in `tests/safeguardjavaclient/.../ToolOptions.java`
2. Add the handling logic in `tests/safeguardjavaclient/.../SafeguardJavaClient.java`
3. Add framework support in `TestFramework/SafeguardTestFramework.psm1` if needed
4. Rebuild the test tool before running tests

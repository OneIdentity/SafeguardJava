# AGENTS.md -- SafeguardJava

Java SDK for the One Identity Safeguard for Privileged Passwords REST API. Published on
[Maven Central](https://central.sonatype.com/artifact/com.oneidentity.safeguard/safeguardjava)
as `com.oneidentity.safeguard:safeguardjava`.

Targets Java 8 source/target compatibility. Root package:
`com.oneidentity.safeguard.safeguardjava`. Key dependencies: Apache HttpClient 5,
Jackson Databind, Microsoft SignalR Java client, SLF4J logging, Gson (via SignalR).

## Project structure

```
SafeguardJava/
|-- src/main/java/com/oneidentity/safeguard/safeguardjava/
|   |-- Safeguard.java                # Entry point: connect(), A2A, Events, Persist, SPS
|   |-- ISafeguardConnection.java     # Primary connection interface
|   |-- SafeguardConnection.java      # Base connection implementation
|   |-- PersistentSafeguardConnection.java  # Auto-refreshing token decorator
|   |-- ISafeguardA2AContext.java      # A2A context interface
|   |-- SafeguardA2AContext.java       # A2A context implementation
|   |-- SafeguardForPrivilegedSessions.java  # SPS entry point
|   |-- ISafeguardSessionsConnection.java    # SPS connection interface
|   |-- SafeguardSessionsConnection.java     # SPS connection implementation
|   |-- authentication/               # IAuthenticationMechanism strategy pattern
|   |   |-- IAuthenticationMechanism.java  # Auth interface contract
|   |   |-- AuthenticatorBase.java    # Shared auth logic (rSTS token exchange)
|   |   |-- PasswordAuthenticator.java    # Username/password via ROG or PKCE
|   |   |-- CertificateAuthenticator.java # Client certificate (keystore/file/thumbprint)
|   |   |-- AccessTokenAuthenticator.java # Pre-existing access token
|   |   |-- AnonymousAuthenticator.java   # Unauthenticated connection
|   |   `-- ManagementServiceAuthenticator.java  # Management service auth
|   |-- event/                        # SignalR-based event system
|   |   |-- ISafeguardEventListener.java  # Event listener interface
|   |   |-- SafeguardEventListener.java   # Standard listener
|   |   |-- PersistentSafeguardEventListener.java    # Auto-reconnecting listener
|   |   |-- PersistentSafeguardA2AEventListener.java # A2A persistent listener
|   |   `-- EventHandlerRegistry.java # Thread-safe handler dispatch
|   |-- restclient/                   # RestClient wraps Apache HttpClient 5
|   |-- data/                         # DTOs and enums (Service, Method, KeyFormat, etc.)
|   `-- exceptions/                   # SafeguardForJavaException, ArgumentException, etc.
|
|-- tests/safeguardjavaclient/        # CLI test tool (interactive, not automated)
|   `-- src/main/java/.../
|       |-- SafeguardJavaClient.java  # Main entry point for test tool
|       `-- ToolOptions.java          # CLI argument definitions
|
|-- TestFramework/                    # PowerShell integration test framework
|   |-- Invoke-SafeguardTests.ps1     # Test runner entry point
|   |-- SafeguardTestFramework.psm1   # Framework module (assertions, helpers, API wrappers)
|   |-- Suites/Suite-*.ps1           # Test suite files (auto-discovered)
|   `-- TestData/CERTS/              # Test certificate data (PEM, PFX, CER files)
|
|-- Samples/                          # Example projects (each with own pom.xml)
|   |-- PasswordConnect/              # Password-based connection example
|   |-- CertificateConnect/           # Certificate-based connection example
|   |-- A2ARetrievalExample/          # A2A credential retrieval example
|   `-- EventListenerExample/         # Event listener example
|
|-- pipeline-templates/                # Azure Pipelines shared templates
|   |-- global-variables.yml          # Pipeline-level vars: semanticVersion, isPrerelease, versionSuffix
|   |-- job-variables.yml             # Job-level vars: version, targetDir, gpgKeyName
|   `-- build-steps.yml               # Parameterized build template (Maven + optional JAR signing)
|
|-- pom.xml                           # Maven build descriptor
|-- azure-pipelines.yml               # CI/CD pipeline definition (two jobs)
|-- .editorconfig                     # Code style enforcement (LF line endings)
|-- spotbugs-exclude.xml              # SpotBugs exclusions
|-- settings/settings.xml             # Maven settings for release publishing
`-- .github/copilot-instructions.md   # Copilot custom instructions
```

## Setup and build commands

**Prerequisites:** JDK 8+ and Maven 3.0.5+. Maven does not need to be on PATH.

```bash
# Standard build (compile + editorconfig check + spotbugs + package)
mvn package

# Quick build (skip static analysis for faster iteration)
mvn package -Dspotbugs.skip=true

# Build with a specific version
mvn package -Drevision=8.2.0

# Clean build
mvn clean package

# Editorconfig check only
mvn editorconfig:check

# Build for release (includes source jars, javadoc, GPG signing)
mvn deploy -P release --settings settings/settings.xml
```

**PowerShell note:** When running Maven from PowerShell, `-D` flags get parsed by
PowerShell's parameter parser. You must quote them:

```powershell
# WRONG — PowerShell interprets -D as a parameter
mvn package -Dspotbugs.skip=true

# CORRECT — quoted to prevent PowerShell parsing
mvn package "-Dspotbugs.skip=true"
& "C:\path\to\mvn.cmd" clean package "-Dspotbugs.skip=true"
```

The build must complete with **0 errors**. The project enforces:
- **EditorConfig** — LF line endings, UTF-8, 4-space indentation (via `editorconfig-maven-plugin`)
- **SpotBugs** — static analysis for bug patterns (via `spotbugs-maven-plugin`)

If you introduce a warning or violation, fix it before considering the change complete.

## Line endings (CRITICAL on Windows)

The `.editorconfig` enforces `end_of_line = lf` for all text files, and the
`editorconfig-maven-plugin` checks this during every build. On Windows, many tools
(including editors and file creation APIs) default to CRLF line endings.

**Every file you create or modify must have LF line endings.** If you are an AI agent
creating files on Windows, post-process every file after creation or modification:

```powershell
$content = [System.IO.File]::ReadAllText($path)
$fixed = $content.Replace("`r`n", "`n")
[System.IO.File]::WriteAllText($path, $fixed, [System.Text.UTF8Encoding]::new($false))
```

The `.editorconfig` excludes `*.{pfx,cer,pvk}` from line ending checks because these
are binary/DER-encoded certificate files.

The `.gitattributes` file controls Git line ending behavior. The global `core.autocrlf`
setting may conflict — the `.gitattributes` overrides take precedence for tracked files.

## Linting and static analysis

Two checks are integrated into the Maven build:

| Tool | Plugin | Purpose |
|---|---|---|
| EditorConfig | `editorconfig-maven-plugin` | Line endings, encoding, indentation |
| SpotBugs | `spotbugs-maven-plugin` | Static analysis for common bug patterns |

Both run during `mvn package`. To skip SpotBugs for faster iteration:

```bash
mvn package -Dspotbugs.skip=true
```

SpotBugs exclusions are defined in `spotbugs-exclude.xml`. When adding new exclusions,
prefer fixing the code over suppressing the warning.

## Testing against a live appliance

This SDK interacts with a live Safeguard appliance API. **There are no mock/unit tests.**
The `tests/` directory contains a CLI test tool and the `TestFramework/` directory contains
a PowerShell integration test framework. Running tests against a live appliance is the only
way to validate changes.

### Asking the user for appliance access

**If you are making non-trivial code changes, ask the user whether they have access to a
live Safeguard appliance for testing.** If they do, ask for:

1. **Appliance address** (IP or hostname of a Safeguard for Privileged Passwords appliance)
2. **Admin password** (for the built-in `admin` account — the bootstrap administrator)
3. *(Optional)* **SPS appliance address** (for Safeguard for Privileged Sessions tests)
4. *(Optional)* **SPS credentials** (username and password for the SPS appliance)

This is not required for documentation or minor fixes, but it is **strongly encouraged**
for any change that touches authentication, API calls, connection logic, event handling,
or streaming.

### Connecting to the appliance (PKCE vs Resource Owner Grant)

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

### Running the PowerShell test suite

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

### Current test suites

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

### Running the CLI test tool directly

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

### Module-to-suite mapping

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

### Fixing test failures

When a test fails, **investigate and fix the source code first** — do not change the test
to make it pass without asking the user. The test suite exists to catch regressions.

Only modify a test if:
- The test itself has a genuine bug (wrong assertion logic, stale assumptions)
- The user explicitly approves changing the test
- A new feature intentionally changes behavior and the test needs updating

Always ask the user before weakening or removing an assertion.

## Exploring the Safeguard API

The appliance exposes Swagger UI for each service at:
- `https://<appliance>/service/core/swagger` — Core service (assets, users, policies, requests)
- `https://<appliance>/service/appliance/swagger` — Appliance service (networking, diagnostics, backups)
- `https://<appliance>/service/notification/swagger` — Notification service (status, events)
- `https://<appliance>/service/event/swagger` — Event service (SignalR streaming)

Use Swagger to discover endpoints, required fields, query parameters, and response schemas.
The default API version is **v4** (since SDK 7.0). Pass `apiVersion` parameter to use v3.

## Architecture

### Entry point (`Safeguard.java`)

The static `Safeguard` class is the SDK's public entry point. All SDK usage starts through
static factory methods:

- **`Safeguard.connect(...)`** — Creates `ISafeguardConnection` instances. Multiple
  overloads support password, certificate (keystore/file/thumbprint/byte array), and
  access token authentication.
- **`Safeguard.A2A.getContext(...)`** — Creates `ISafeguardA2AContext` for
  application-to-application credential retrieval. Only supports certificate authentication.
- **`Safeguard.A2A.Events.getPersistentA2AEventListener(...)`** — Creates auto-reconnecting
  A2A event listeners.
- **`Safeguard.Persist(connection)`** — Wraps any connection in a
  `PersistentSafeguardConnection` that auto-refreshes tokens.
- **`SafeguardForPrivilegedSessions.Connect(...)`** — Creates
  `ISafeguardSessionsConnection` for Safeguard for Privileged Sessions (SPS).

### Safeguard API services

The SDK targets five backend services, represented by the `Service` enum:

| Service | Endpoint pattern | Auth required |
|---|---|---|
| `Core` | `/service/core/v{version}` | Yes |
| `Appliance` | `/service/appliance/v{version}` | Yes |
| `Notification` | `/service/notification/v{version}` | No |
| `A2A` | `/service/a2a/v{version}` | Certificate |
| `Management` | `/service/management/v{version}` | Yes |

### Authentication strategy pattern (`authentication/`)

All authenticators implement `IAuthenticationMechanism`. When adding a new authentication
method:
1. Implement `IAuthenticationMechanism` in the `authentication/` package
2. Add `Safeguard.connect()` overload(s) in `Safeguard.java`
3. Follow the pattern of existing authenticators (extend `AuthenticatorBase`)

### Connection classes

- **`SafeguardConnection`** — Base `ISafeguardConnection` implementation. Makes HTTP calls
  via `invokeMethod()` / `invokeMethodFull()`.
- **`PersistentSafeguardConnection`** — Decorator that checks
  `getAccessTokenLifetimeRemaining() <= 0` before each call and auto-refreshes tokens.

### rSTS authentication flow

All authenticators obtain tokens via the embedded Safeguard RSTS (Resource Security Token
Service) at `https://{host}/RSTS/oauth2/token`.

- **Password authentication** uses the `password` grant type (Resource Owner Grant). **ROG
  is disabled by default** on modern Safeguard appliances. If ROG is disabled, password
  auth will fail with a 400 error. It must be explicitly enabled via appliance settings
  or the test framework's preflight check.
- **PKCE authentication** (`PasswordAuthenticator` with `usePkce=true`) drives the rSTS
  login controller at `/RSTS/UserLogin/LoginController` programmatically, exchanging an
  authorization code for a token. **PKCE is always available** regardless of ROG settings
  and is the preferred method for interactive/programmatic login.
- **Certificate authentication** uses the `client_credentials` grant type with a client
  certificate.
- **Access token authentication** accepts a pre-obtained token but cannot refresh it.

The test framework handles ROG automatically — it enables ROG before tests run and
restores the original setting when tests complete. Both ROG and PKCE are valid for tests;
use whichever is appropriate for the feature being tested.

### Event listeners (`event/`)

- **`SafeguardEventListener`** — Standard SignalR listener. Does NOT survive prolonged outages.
- **`PersistentSafeguardEventListener`** — Auto-reconnecting persistent listener.
- **`PersistentSafeguardA2AEventListener`** — Persistent A2A-specific variant.
- **`EventHandlerRegistry`** — Thread-safe handler dispatch. Each event type gets its own
  handler thread; handlers for the same event execute sequentially, handlers for different
  events execute concurrently.
- Use `getPersistentEventListener()` for production deployments.
- Event handling code **must use Gson** `JsonElement`/`JsonObject` types (transitive from
  the SignalR Java client's `GsonHubProtocol`).

### A2A (`SafeguardA2AContext`)

Certificate-only authentication for automated credential retrieval. Key types:
`ISafeguardA2AContext`, `A2ARegistration`, `BrokeredAccessRequest`.

### SPS integration (`SafeguardForPrivilegedSessions`)

Integration with Safeguard for Privileged Sessions. `ISafeguardSessionsConnection` /
`SafeguardSessionsConnection`. Connects using basic auth (username/password) over HTTPS.

## Code conventions

### Sensitive data as `char[]`

Passwords, access tokens, and API keys are stored as `char[]` rather than `String` to
allow explicit clearing from memory. Follow this pattern in all new code that handles
credentials.

### Interface-first design

Every public type has a corresponding `I`-prefixed interface (`ISafeguardConnection`,
`ISafeguardA2AContext`, `ISafeguardEventListener`, `IAuthenticationMechanism`). Code
against interfaces, not implementations.

### Dispose pattern

Connections, A2A contexts, and event listeners implement a `dispose()` method that must
be called to release resources. Every public method on these classes guards against
use-after-dispose:

```java
if (disposed) {
    throw new ObjectDisposedException("ClassName");
}
```

Follow this pattern in any new connection or context class.

### Error handling

- Parameter validation throws `ArgumentException`
- HTTP failures throw `SafeguardForJavaException` with status code and response body
- Null HTTP responses throw `SafeguardForJavaException("Unable to connect to ...")`
- Disposed object access throws `ObjectDisposedException`

### SSL/TLS

- `ignoreSsl=true` uses `NoopHostnameVerifier` (development only)
- Custom `HostnameVerifier` callback for fine-grained validation
- Default: standard Java certificate validation
- Certificate contexts (`CertificateContext`) support JKS keystores, PFX files, byte
  arrays, and Windows certificate store (by thumbprint)
- **Never recommend `ignoreSsl` for production** without explicit warning

### Logging

Uses **SLF4J** as the logging facade. The SLF4J dependency provides the facade for both
the SDK and the SignalR library. Users supply their own SLF4J binding (e.g., Logback,
Log4j2, JUL bridge) at runtime.

### Naming conventions

- Java standard naming: camelCase for fields/methods, PascalCase for classes
- Interfaces use `I` prefix: `ISafeguardConnection`, `IAuthenticationMechanism`
- Constants: UPPER_SNAKE_CASE
- Package: `com.oneidentity.safeguard.safeguardjava`

### Java version

The SDK targets **Java 8** source/target compatibility. Do not use language features
from Java 9+ (var, modules, records, sealed classes, etc.). All dependencies must be
compatible with Java 8.

## CI/CD

The project uses **Azure Pipelines** (`azure-pipelines.yml`) with shared templates in
`pipeline-templates/`.

### Pipeline architecture

The pipeline has **two jobs**, matching the SafeguardDotNet pattern:

| Job | Runs when | What it does |
|---|---|---|
| **PRValidation** | Pull requests only | `mvn package` — compile, lint, SpotBugs |
| **BuildAndPublish** | Merges to `master`/`release-*` | Build, GPG sign, JAR sign, publish to Maven Central + GitHub Packages, create GitHub Release |

Both jobs share `build-steps.yml` with different parameters. PRValidation uses defaults
(`package`, no signing); BuildAndPublish passes `deploy`, release profile flags, and
`signJars: true`.

### Pipeline template files

| File | Scope | Contents |
|---|---|---|
| `global-variables.yml` | Pipeline-level | `semanticVersion`, `isPrerelease`, `versionSuffix` |
| `job-variables.yml` | Job-level | `version` (composed), `targetDir`, `gpgKeyName` |
| `build-steps.yml` | Steps template | Maven task + optional Docker JAR signing + artifact publishing |

### Version strategy

Version is composed from runtime variables: `$(semanticVersion).$(Build.BuildId)$(versionSuffix)`

- When `isPrerelease: 'true'` → `versionSuffix` is `-SNAPSHOT` → e.g. `8.2.0.355537-SNAPSHOT`
- When `isPrerelease: 'false'` → `versionSuffix` is empty → e.g. `8.2.0.355537`

The pom.xml uses `<version>${revision}</version>` with CI-friendly properties. The actual
version is always injected via `-Drevision=$(version)` on the Maven command line.

### Service connections and key vaults

| Service connection | Key vault | Secrets |
|---|---|---|
| `SafeguardOpenSource` | `SafeguardBuildSecrets` | `SonatypeUserToken`, `SonatypeRepositoryPassword`, `GpgCodeSigningKey`, `SigningStorePassword`, `GitHubPackagesToken` |
| `OneIdentity.Infrastructure.SPPCodeSigning` | `SPPCodeSigning` | `SPPCodeSigning-Password`, `SPPCodeSigning-TotpPrivateKey` |
| `PangaeaBuild-GitHub` | *(none)* | GitHub service connection for Release creation |

### Two signing mechanisms

The pipeline uses **two independent signing mechanisms** that serve different purposes:

**1. GPG signing (`maven-gpg-plugin`)** — Produces `.asc` detached signature files required
by Maven Central for release validation. Configured in the `release` Maven profile.

- GPG private key: vault secret `GpgCodeSigningKey`, imported via `gpg --batch --import`
- GPG passphrase: vault secret `SigningStorePassword`
- `settings/settings.xml` maps the passphrase via a server entry:
  `<id>${gpgkeyname}</id>` + `<passphrase>${signingkeystorepassword}</passphrase>`
- Maven command line needs both `-Dsigningkeystorepassword=$(SigningStorePassword)` and
  `-Dgpgkeyname=$(gpgKeyName)`
- The plugin uses `--batch --pinentry-mode loopback` for non-interactive passphrase input
- **CRITICAL:** The GPG plugin is bound to the `verify` lifecycle phase. `mvn package`
  stops at the `package` phase and **never triggers GPG signing**. Only `mvn deploy`
  (or `mvn verify` / `mvn install`) reaches the GPG plugin. This means you cannot test
  GPG signing with `mvn package -P release` — it will succeed silently without signing.

**2. JAR code signing (SSL.com CodeSigner Docker image)** — Embeds certificates in
`META-INF/` (CERT.SF, CERT.RSA) inside the JAR for Java runtime signature verification.

- Uses Docker image `ghcr.io/sslcom/codesigner:latest` which bundles its own JRE
- eSigner account: `ssl.oid.safeguardpp@groups.quest.com`
- Credentials: `SPPCodeSigning-Password` (password) + `SPPCodeSigning-TotpPrivateKey` (TOTP)
- The `-override` flag signs the JAR **in place** (no separate output file)
- `ENVIRONMENT_NAME=PROD` is required for production signing (vs sandbox)
- No `CREDENTIAL_ID` is needed when the eSigner account has only one certificate
- Runs as a **post-build step** after Maven completes, not as a Maven plugin

### CodeSignTool pitfalls (IMPORTANT)

**Do NOT attempt to run CodeSignTool directly on the build agent.** The standalone
CodeSignTool v1.3.2 is compiled for Java 11 and has strict JVM compatibility requirements:

- **Java 8** → `UnsupportedClassVersionError` (class file version 55.0, needs Java 11+)
- **Java 11** → Works, but requires a separate JDK install on the build agent
- **Java 17+** → `IllegalAccessError` due to JPMS module access restrictions

The **Docker image is the correct approach** — it bundles a compatible JRE inside the
container, isolating CodeSignTool from the host Java version entirely. The build agent
only needs Docker installed (which Azure Pipelines `ubuntu-latest` provides by default).

### Maven Central publishing

Publishing uses the `central-publishing-maven-plugin` v0.7.0 with `autoPublish: false`
and `waitUntil: validated`. The plugin's `publishingServerId: central` maps to the
`<server id="central">` entry in `settings/settings.xml`.

**SNAPSHOT publishing** requires:
- `central-publishing-maven-plugin` v0.7.0+ (earlier versions don't support SNAPSHOTs)
- Explicit enablement per namespace at central.sonatype.com → Namespaces → dropdown →
  "Enable SNAPSHOTs"
- Without enablement, SNAPSHOT deploys return **403 Forbidden**
- SNAPSHOTs are not validated, can be overwritten, and are cleaned up after ~90 days

### GitHub Packages publishing

Uses `mvn deploy:deploy-file` with explicit artifact coordinates. **Do NOT use
`-DpomFile=pom.xml`** — the `deploy-file` goal reads the pom literally without resolving
Maven properties. Since our pom has `<version>${revision}</version>`, it would see
`${revision}` as the literal version string (invalid characters: `$`, `{`, `}`). Instead,
specify coordinates directly: `-DgroupId=... -DartifactId=... -Dversion=... -Dpackaging=jar`.

Authentication uses a `<server id="github">` entry in `settings/settings.xml` with
`${githubusername}` and `${githubtoken}` properties, resolved via `-D` flags on the
command line.

### Azure Pipelines variable scoping (CRITICAL pitfall)

Azure Pipelines has two expression syntaxes with **very different scoping rules**:

- **`${{ variables.X }}`** — Compile-time expression. Can **only** see variables defined
  in the **same template file**. Variables from other templates are invisible at compile
  time, even if they are in the same pipeline.
- **`$(X)`** — Runtime macro. Resolves **after** all variable scopes (pipeline + job) are
  merged. Works across template boundaries.

This means:
- `${{ if eq(variables.isPrerelease, 'true') }}` in `job-variables.yml` **cannot** see
  `isPrerelease` defined in `global-variables.yml` — it will always evaluate to false.
- The fix: compute dependent values (like `versionSuffix`) in the **same template** as
  the variables they reference, then use `$(versionSuffix)` runtime macros elsewhere.
- Also note: `${{ true }}` as a variable value becomes the string `'True'` (capital T).
  Use the string `'true'` (lowercase) to avoid comparison mismatches.

### Pipeline modification checklist

When modifying the CI/CD pipeline:
1. **Test GPG signing with `mvn deploy`**, not `mvn package` (GPG is in `verify` phase)
2. **Never use `-DpomFile=pom.xml`** with `deploy:deploy-file` — use explicit coordinates
3. **Keep compile-time conditionals in the same template** as the variables they reference
4. **Use string `'true'`/`'false'`** for boolean pipeline variables, not `${{ true }}`
5. **Verify CodeSignTool via Docker only** — never install it directly on the build agent
6. **All credentials flow through `settings/settings.xml`** via Maven property placeholders
   resolved by `-D` flags — Azure DevOps auto-masks vault secrets in logs

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

## Samples

The `Samples/` directory contains standalone example projects, each with its own `pom.xml`:

| Sample | Description |
|---|---|
| `PasswordConnect` | Password-based authentication and API call |
| `CertificateConnect` | Certificate-based authentication via PFX/JKS |
| `A2ARetrievalExample` | Application-to-application credential retrieval |
| `EventListenerExample` | Persistent event listener with SignalR |

Each sample is self-contained and can be built independently:

```bash
cd Samples/PasswordConnect
mvn package
java -jar target/PasswordConnect-1.0.jar
```

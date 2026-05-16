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
|-- TestFramework/                    # PowerShell integration test framework
|-- Samples/                          # Example projects (each with own pom.xml)
|-- pipeline-templates/               # Azure Pipelines shared templates
|-- pom.xml                           # Maven build descriptor
|-- azure-pipelines.yml               # CI/CD pipeline definition
|-- spotbugs-exclude.xml              # SpotBugs exclusions
`-- settings/settings.xml             # Maven settings for release publishing
```

## Setup and build commands

**Prerequisites:** JDK 8+ and Maven 3.0.5+.

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
```

**PowerShell note:** Quote `-D` flags to prevent PowerShell's parameter parser from
consuming them:

```powershell
# WRONG — PowerShell interprets -D as a parameter
mvn package -Dspotbugs.skip=true

# CORRECT
mvn package "-Dspotbugs.skip=true"
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

## Exploring the Safeguard API

The appliance exposes Swagger UI for each service at:
- `https://<appliance>/service/core/swagger` — Core service (assets, users, policies, requests)
- `https://<appliance>/service/appliance/swagger` — Appliance service (networking, diagnostics, backups)
- `https://<appliance>/service/notification/swagger` — Notification service (status, events)
- `https://<appliance>/service/event/swagger` — Event service (SignalR streaming)

The default API version is **v4** (since SDK 7.0). Pass `apiVersion` parameter to use v3.

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

### Error handling

- Parameter validation throws `ArgumentException`
- HTTP failures throw `SafeguardForJavaException` with status code and response body
- Null HTTP responses throw `SafeguardForJavaException("Unable to connect to ...")`
- Disposed object access throws `ObjectDisposedException`

### SSL/TLS

- `ignoreSsl=true` uses `NoopHostnameVerifier` (development only)
- Custom `HostnameVerifier` callback for fine-grained validation
- Default: standard Java certificate validation
- **Never recommend `ignoreSsl` for production** without explicit warning

### Logging

Uses **SLF4J** as the logging facade. Users supply their own SLF4J binding at runtime.

### Naming conventions

- Java standard naming: camelCase for fields/methods, PascalCase for classes
- Interfaces use `I` prefix: `ISafeguardConnection`, `IAuthenticationMechanism`
- Constants: UPPER_SNAKE_CASE
- Package: `com.oneidentity.safeguard.safeguardjava`

### Java version

The SDK targets **Java 8** source/target compatibility. Do not use language features
from Java 9+ (var, modules, records, sealed classes, etc.). All dependencies must be
compatible with Java 8.

## CI/CD overview

The project uses **Azure Pipelines** (`azure-pipelines.yml`) with two jobs:
- **PRValidation** — runs `mvn package` on pull requests (compile, lint, SpotBugs)
- **BuildAndPublish** — on merge to `master`/`release-*`: build, sign, publish to
  Maven Central + GitHub Packages, create GitHub Release

See the `ci-cd-pipeline` skill for signing details, publishing configuration, and
critical pipeline pitfalls.

## Samples

The `Samples/` directory contains standalone example projects, each with its own `pom.xml`:

| Sample | Description |
|---|---|
| `PasswordConnect` | Password-based authentication and API call |
| `CertificateConnect` | Certificate-based authentication via PFX/JKS |
| `A2ARetrievalExample` | Application-to-application credential retrieval |
| `EventListenerExample` | Persistent event listener with SignalR |

## On-demand skills

The following skills contain deeper reference material loaded only when relevant.
Read the `SKILL.md` when your current task matches the trigger.

| Skill | When to read | File |
|-------|-------------|------|
| Testing Guide | Running tests, writing tests, investigating test failures, testing against a live appliance | `.agents/skills/testing-guide/SKILL.md` |
| Architecture | Working on SDK internals, auth flows, event listeners, connection classes, adding new auth methods | `.agents/skills/architecture/SKILL.md` |
| CI/CD Pipeline | Modifying Azure Pipelines, build templates, signing, publishing, release process | `.agents/skills/ci-cd-pipeline/SKILL.md` |

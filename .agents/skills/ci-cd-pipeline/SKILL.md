---
name: ci-cd-pipeline
description: >-
  Use when modifying Azure Pipelines, build templates, signing
  configuration, Maven Central publishing, GitHub Packages publishing,
  or release process. Covers GPG signing, JAR code signing, version
  strategy, and critical pipeline pitfalls.
---

# CI/CD Pipeline

The project uses **Azure Pipelines** (`azure-pipelines.yml`) with shared templates in
`pipeline-templates/`.

## Pipeline architecture

The pipeline has **two jobs**, matching the SafeguardDotNet pattern:

| Job | Runs when | What it does |
|---|---|---|
| **PRValidation** | Pull requests only | `mvn package` — compile, lint, SpotBugs |
| **BuildAndPublish** | Merges to `master`/`release-*` | Build, GPG sign, JAR sign, publish to Maven Central + GitHub Packages, create GitHub Release |

Both jobs share `build-steps.yml` with different parameters. PRValidation uses defaults
(`package`, no signing); BuildAndPublish passes `deploy`, release profile flags, and
`signJars: true`.

## Pipeline template files

| File | Scope | Contents |
|---|---|---|
| `global-variables.yml` | Pipeline-level | `semanticVersion`, `isPrerelease`, `versionSuffix` |
| `job-variables.yml` | Job-level | `version` (composed), `targetDir`, `gpgKeyName` |
| `build-steps.yml` | Steps template | Maven task + optional Docker JAR signing + artifact publishing |

## Version strategy

Version is composed from runtime variables: `$(semanticVersion).$(Build.BuildId)$(versionSuffix)`

- When `isPrerelease: 'true'` → `versionSuffix` is `-SNAPSHOT` → e.g. `8.2.0.355537-SNAPSHOT`
- When `isPrerelease: 'false'` → `versionSuffix` is empty → e.g. `8.2.0.355537`

The pom.xml uses `<version>${revision}</version>` with CI-friendly properties. The actual
version is always injected via `-Drevision=$(version)` on the Maven command line.

## Service connections and key vaults

| Service connection | Key vault | Secrets |
|---|---|---|
| `SafeguardOpenSource` | `SafeguardBuildSecrets` | `SonatypeUserToken`, `SonatypeRepositoryPassword`, `GpgCodeSigningKey`, `SigningStorePassword`, `GitHubPackagesToken` |
| `OneIdentity.Infrastructure.SPPCodeSigning` | `SPPCodeSigning` | `SPPCodeSigning-Password`, `SPPCodeSigning-TotpPrivateKey` |
| `PangaeaBuild-GitHub` | *(none)* | GitHub service connection for Release creation |

## Two signing mechanisms

The pipeline uses **two independent signing mechanisms** that serve different purposes:

### 1. GPG signing (`maven-gpg-plugin`)

Produces `.asc` detached signature files required by Maven Central for release validation.
Configured in the `release` Maven profile.

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

### 2. JAR code signing (SSL.com CodeSigner Docker image)

Embeds certificates in `META-INF/` (CERT.SF, CERT.RSA) inside the JAR for Java runtime
signature verification.

- Uses Docker image `ghcr.io/sslcom/codesigner:latest` which bundles its own JRE
- eSigner account: `ssl.oid.safeguardpp@groups.quest.com`
- Credentials: `SPPCodeSigning-Password` (password) + `SPPCodeSigning-TotpPrivateKey` (TOTP)
- The `-override` flag signs the JAR **in place** (no separate output file)
- `ENVIRONMENT_NAME=PROD` is required for production signing (vs sandbox)
- No `CREDENTIAL_ID` is needed when the eSigner account has only one certificate
- Runs as a **post-build step** after Maven completes, not as a Maven plugin

## CodeSignTool pitfalls (IMPORTANT)

**Do NOT attempt to run CodeSignTool directly on the build agent.** The standalone
CodeSignTool v1.3.2 is compiled for Java 11 and has strict JVM compatibility requirements:

- **Java 8** → `UnsupportedClassVersionError` (class file version 55.0, needs Java 11+)
- **Java 11** → Works, but requires a separate JDK install on the build agent
- **Java 17+** → `IllegalAccessError` due to JPMS module access restrictions

The **Docker image is the correct approach** — it bundles a compatible JRE inside the
container, isolating CodeSignTool from the host Java version entirely. The build agent
only needs Docker installed (which Azure Pipelines `ubuntu-latest` provides by default).

## Maven Central publishing

Publishing uses the `central-publishing-maven-plugin` v0.7.0 with `autoPublish: false`
and `waitUntil: validated`. The plugin's `publishingServerId: central` maps to the
`<server id="central">` entry in `settings/settings.xml`.

**SNAPSHOT publishing** requires:
- `central-publishing-maven-plugin` v0.7.0+ (earlier versions don't support SNAPSHOTs)
- Explicit enablement per namespace at central.sonatype.com → Namespaces → dropdown →
  "Enable SNAPSHOTs"
- Without enablement, SNAPSHOT deploys return **403 Forbidden**
- SNAPSHOTs are not validated, can be overwritten, and are cleaned up after ~90 days

## GitHub Packages publishing

Uses `mvn deploy:deploy-file` with explicit artifact coordinates. **Do NOT use
`-DpomFile=pom.xml`** — the `deploy-file` goal reads the pom literally without resolving
Maven properties. Since our pom has `<version>${revision}</version>`, it would see
`${revision}` as the literal version string (invalid characters: `$`, `{`, `}`). Instead,
specify coordinates directly: `-DgroupId=... -DartifactId=... -Dversion=... -Dpackaging=jar`.

Authentication uses a `<server id="github">` entry in `settings/settings.xml` with
`${githubusername}` and `${githubtoken}` properties, resolved via `-D` flags on the
command line.

## Azure Pipelines variable scoping (CRITICAL pitfall)

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

### Example of the scoping pitfall

```yaml
# global-variables.yml — defines isPrerelease
variables:
  isPrerelease: 'true'

# job-variables.yml — WRONG: can't see isPrerelease from global-variables.yml
variables:
  versionSuffix: ${{ if eq(variables.isPrerelease, 'true') }}-SNAPSHOT${{ else }}${{ endif }}
  # ↑ Always evaluates to empty string because isPrerelease is invisible here

# FIX: compute versionSuffix in global-variables.yml alongside isPrerelease,
# then reference as $(versionSuffix) runtime macro in job-variables.yml
```

## Pipeline modification checklist

When modifying the CI/CD pipeline:
1. **Test GPG signing with `mvn deploy`**, not `mvn package` (GPG is in `verify` phase)
2. **Never use `-DpomFile=pom.xml`** with `deploy:deploy-file` — use explicit coordinates
3. **Keep compile-time conditionals in the same template** as the variables they reference
4. **Use string `'true'`/`'false'`** for boolean pipeline variables, not `${{ true }}`
5. **Verify CodeSignTool via Docker only** — never install it directly on the build agent
6. **All credentials flow through `settings/settings.xml`** via Maven property placeholders
   resolved by `-D` flags — Azure DevOps auto-masks vault secrets in logs

## Full deploy command reference

The complete `mvn deploy` invocation for a release build (for reference):

```bash
mvn deploy -P release \
    --settings settings/settings.xml \
    "-Drevision=$(version)" \
    "-Dsigningkeystorepassword=$(SigningStorePassword)" \
    "-Dgpgkeyname=$(gpgKeyName)" \
    "-Dcentralusername=$(SonatypeUserToken)" \
    "-Dcentralpassword=$(SonatypeRepositoryPassword)"
```

All `-D` properties map to `<server>` entries in `settings/settings.xml` via Maven
property placeholders (e.g., `<passphrase>${signingkeystorepassword}</passphrase>`).
Azure DevOps automatically masks vault secrets in log output.

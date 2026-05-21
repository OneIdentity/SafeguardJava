# AGENTS.md -- SafeguardJava

Java SDK for the One Identity Safeguard REST API.
Artifact: `com.oneidentity.safeguard:safeguardjava`.

## Project structure

- `src/main/java/com/oneidentity/safeguard/safeguardjava/` — SDK sources (`Safeguard`, connections, A2A, auth, events, restclient, data, exceptions)
- `tests/safeguardjavaclient/` — interactive live-appliance Java test client
- `TestFramework/` — PowerShell appliance-test scaffolding
- `Samples/` — standalone sample Maven projects
- `.agents/skills/` — on-demand guidance
- `pipeline-templates/`, `azure-pipelines.yml` — CI definitions
- `pom.xml`, `settings/settings.xml`, `spotbugs-exclude.xml` — build, publishing, static analysis

## Setup and build

**Prerequisites:** JDK 8+ and Maven 3.0.5+.

```bash
mvn package
mvn verify
mvn clean verify
mvn package "-Dspotbugs.skip=true"
```

In PowerShell, quote `-D...` flags. For endpoint discovery, use
`https://<address>/service/<service>/swagger`; see `api-patterns`.

## Linting

- `mvn editorconfig:check` — formatting and LF line endings
- `mvn verify` — EditorConfig + SpotBugs through Maven

## Testing

There is no root-level mock/unit suite. Use:

- `mvn verify`
- `tests/safeguardjavaclient/`
- `TestFramework/`
- `Samples/`

See `testing-guide` for setup and workflow details.

## Code conventions

- keep passwords, tokens, API keys, and certificate passwords as `char[]`, then clear them
- code against `I`-prefixed interfaces (`ISafeguardConnection`, `ISafeguardA2AContext`, `ISafeguardEventListener`, `IAuthenticationMechanism`)
- call `dispose()` on connections, A2A contexts, and listeners
- expect `ArgumentException`, `SafeguardForJavaException`, and `ObjectDisposedException`
- preserve Java 8 compatibility and standard Java naming
- do not recommend `ignoreSsl=true` for production without a warning
- keep repository text files on **LF** line endings, especially on Windows

## CI/CD

See the `build-and-release` skill.

## Security

- never commit real passwords, API keys, access tokens, PFX/JKS files, private keys, or signing secrets
- treat certificate material and retrieved secrets as sensitive runtime data
- keep docs and samples scrubbed of real appliance addresses and credentials
- prefer trusted certificates over disabling SSL checks

## Versioning

- the Maven package version comes from `${revision}` in `pom.xml`
- release automation injects the effective version with `-Drevision=...`
- the default Safeguard API version is **v4**; pass `apiVersion` for older endpoints
- preserve Java 8 compatibility in public APIs and examples

## On-demand skills

| Skill | When to read | File |
|---|---|---|
| Build and Release | Pipelines, signing, publishing, releases | `.agents/skills/build-and-release/SKILL.md` |
| API Patterns | Standard REST calls, bodies, query params, responses | `.agents/skills/api-patterns/SKILL.md` |
| A2A Workflow | A2A contexts, API keys, brokering, A2A events | `.agents/skills/a2a-workflow/SKILL.md` |
| Testing Guide | Live-appliance validation and test workflows | `.agents/skills/testing-guide/SKILL.md` |
| Architecture | SDK internals, auth flows, listeners, connections | `.agents/skills/architecture/SKILL.md` |

## Samples

| Sample | Description |
|---|---|
| `PasswordConnect` | Password auth + `GET Me` |
| `CertificateConnect` | PKCS12/PFX certificate auth |
| `A2ARetrievalExample` | A2A credential retrieval |
| `EventListenerExample` | Persistent SignalR listener |

## Keeping this file current

Keep this file short and always-on. Move deep procedures into `.agents/skills/`, and
update structure/build/test/security pointers when workflows change.

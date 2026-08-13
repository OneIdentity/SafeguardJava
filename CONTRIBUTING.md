# Contributing to SafeguardJava

Thanks for your interest in improving SafeguardJava, the Java SDK for the
One Identity Safeguard Web API.

## Reporting issues

- **Bugs and feature requests:** open a GitHub Issue.
- **Security vulnerabilities:** do **not** open a public issue — follow
  [SECURITY.md](SECURITY.md).

## Prerequisites

- [JDK 8](https://adoptium.net) or later (JDK 9+ is required at runtime for
  the SignalR event-listener feature).
- [Maven 3.0.5](https://maven.apache.org/download.cgi) or later.
- (Optional) a Safeguard for Privileged Passwords appliance for the
  interactive Java test client under `tests/safeguardjavaclient/`.

## Building

    mvn package

## Testing

`mvn verify` runs the hermetic Surefire unit tests plus the EditorConfig
and SpotBugs checks — no appliance required:

    mvn clean verify

The interactive, live-appliance client lives under
`tests/safeguardjavaclient/`.

## Coding conventions

Static analysis runs during `mvn verify` (EditorConfig line-ending checks
and SpotBugs). See [AGENTS.md](AGENTS.md) for the full conventions.

## Submitting changes

1. Fork the repository and create a feature branch.
2. Keep commits focused with clear messages.
3. Ensure `mvn clean verify` passes (unit tests, EditorConfig, SpotBugs).
4. Open a pull request describing the behavior you changed and the tests
   that prove it.
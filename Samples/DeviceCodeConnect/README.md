# DeviceCodeConnect Sample

Demonstrates connecting to Safeguard using the OAuth 2.0 Device Authorization
Grant (Device Code flow, RFC 8628). This flow is designed for **headless or
no-browser** environments (containers, SSH sessions, CI jobs, IoT or constrained
devices).

The SDK never opens a browser. This sample prints a verification URL and a user
code through the required display callback; you complete authentication in a
browser on any device, and the SDK polls until login succeeds, is denied,
expires, or is cancelled.

> Printing the URL and code is **sample behavior**. The library only hands those
> values to the callback — it never prints, logs, or opens a browser itself, and
> it never exposes the internal `device_code`.

## Appliance prerequisite

The Device Code grant must be enabled on the appliance under
**Settings → OAuth 2.0 Grant Types** (the API setting
`Settings/Allowed OAuth2 Grant Types` must include `DeviceCode`). When it is
disabled, the SDK throws a clear error instructing an administrator to enable it.

## Building

```bash
mvn clean package
```

## Running

```bash
java -jar target/device-code-connect-1.0-SNAPSHOT-jar-with-dependencies.jar <appliance>
```

### Arguments

| Argument | Description | Default |
|----------|-------------|---------|
| appliance | IP or hostname of Safeguard appliance | (required) |

### Example

```bash
java -jar target/device-code-connect-1.0-SNAPSHOT-jar-with-dependencies.jar safeguard.example.com
```

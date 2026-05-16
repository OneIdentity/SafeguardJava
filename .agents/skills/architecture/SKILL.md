---
name: architecture
description: >-
  Use when working on SDK internals, authentication flows, connection
  classes, event listeners, A2A contexts, SPS integration, or adding
  new authentication methods. Covers the rSTS token exchange, strategy
  pattern, and SignalR event system.
---

# Architecture Deep Dive

## Entry point (`Safeguard.java`)

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

## Safeguard API services

The SDK targets five backend services, represented by the `Service` enum:

| Service | Endpoint pattern | Auth required |
|---|---|---|
| `Core` | `/service/core/v{version}` | Yes |
| `Appliance` | `/service/appliance/v{version}` | Yes |
| `Notification` | `/service/notification/v{version}` | No |
| `A2A` | `/service/a2a/v{version}` | Certificate |
| `Management` | `/service/management/v{version}` | Yes |

## Authentication strategy pattern (`authentication/`)

All authenticators implement `IAuthenticationMechanism`. When adding a new authentication
method:
1. Implement `IAuthenticationMechanism` in the `authentication/` package
2. Add `Safeguard.connect()` overload(s) in `Safeguard.java`
3. Follow the pattern of existing authenticators (extend `AuthenticatorBase`)

### Adding a new authentication method — checklist

1. **Create the authenticator class** in `src/.../authentication/`:
   - Extend `AuthenticatorBase` (provides rSTS token exchange logic)
   - Implement `IAuthenticationMechanism` interface methods:
     - `getId()` — unique identifier string
     - `getAccessToken()` — obtain token via rSTS
     - `refreshAccessToken()` — refresh existing token
     - `getAccessTokenLifetimeRemaining()` — seconds until expiry
     - `logout()` — revoke token and clean up
     - `dispose()` — release resources
   - Follow the `char[]` convention for any credential parameters

2. **Add factory overloads** in `Safeguard.java`:
   - Add static `connect()` method(s) with appropriate parameters
   - Include overloads for both `ignoreSsl` boolean and `HostnameVerifier` callback
   - Include overloads with and without `apiVersion` parameter

3. **Wire up connection creation**:
   - Instantiate the authenticator, call `connect()` on it
   - Wrap in `SafeguardConnection` and return as `ISafeguardConnection`

4. **Add tests** — see the testing-guide skill for module-to-suite mapping

## Connection classes

- **`SafeguardConnection`** — Base `ISafeguardConnection` implementation. Makes HTTP calls
  via `invokeMethod()` / `invokeMethodFull()`.
- **`PersistentSafeguardConnection`** — Decorator that checks
  `getAccessTokenLifetimeRemaining() <= 0` before each call and auto-refreshes tokens.

### Token refresh flow in `PersistentSafeguardConnection`

```
Client calls invokeMethod()
  → PersistentSafeguardConnection checks getAccessTokenLifetimeRemaining()
    → If <= 0: calls refreshAccessToken() on the underlying authenticator
    → Delegates to SafeguardConnection.invokeMethod() with refreshed token
```

The decorator is transparent — callers interact with `ISafeguardConnection` identically
regardless of whether persistence is enabled.

## rSTS authentication flow

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

## Event listeners (`event/`)

- **`SafeguardEventListener`** — Standard SignalR listener. Does NOT survive prolonged outages.
- **`PersistentSafeguardEventListener`** — Auto-reconnecting persistent listener.
- **`PersistentSafeguardA2AEventListener`** — Persistent A2A-specific variant.
- **`EventHandlerRegistry`** — Thread-safe handler dispatch. Each event type gets its own
  handler thread; handlers for the same event execute sequentially, handlers for different
  events execute concurrently.
- Use `getPersistentEventListener()` for production deployments.
- Event handling code **must use Gson** `JsonElement`/`JsonObject` types (transitive from
  the SignalR Java client's `GsonHubProtocol`).

### Gson vs Jackson in event handlers (common mistake)

The SignalR Java client uses `GsonHubProtocol`, which means all event payloads arrive as
Gson `JsonElement` objects. Although the SDK uses Jackson Databind for REST API responses,
event handler code must use Gson types:

```java
// CORRECT — Gson types for event payloads
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

handler.setHandler(event -> {
    JsonObject payload = event.getAsJsonObject();
    String name = payload.get("Name").getAsString();
});

// WRONG — Jackson types will fail at runtime
import com.fasterxml.jackson.databind.JsonNode; // Don't use for events
```

## A2A (`SafeguardA2AContext`)

Certificate-only authentication for automated credential retrieval. Key types:
`ISafeguardA2AContext`, `A2ARegistration`, `BrokeredAccessRequest`.

A2A contexts use client certificates to authenticate directly — no username/password
involved. The certificate must be registered as an A2A credential retrieval certificate
on the appliance.

## SPS integration (`SafeguardForPrivilegedSessions`)

Integration with Safeguard for Privileged Sessions. `ISafeguardSessionsConnection` /
`SafeguardSessionsConnection`. Connects using basic auth (username/password) over HTTPS.

SPS has its own REST API at `https://<sps-address>/api/`. The `ISafeguardSessionsConnection`
interface provides `invokeMethod()` / `invokeMethodFull()` similar to the main connection,
but targets the SPS API instead of the SPP API.

## Certificate handling (`CertificateContext`)

The `CertificateContext` class unifies multiple certificate input formats:

| Input format | Method/Constructor | Notes |
|---|---|---|
| JKS keystore | File path + password | Standard Java keystore |
| PFX/PKCS#12 file | File path + password | Cross-platform format |
| Byte array | Raw bytes + password | For certificates stored in memory or database |
| Windows thumbprint | Certificate thumbprint string | Windows certificate store lookup |

When working with certificate authentication, ensure:
- PFX files include the private key (required for client certificate auth)
- The certificate chain is complete (or the CA is trusted by the appliance)
- Passwords are passed as `char[]`, not `String`

---
name: api-patterns
description: Use when making standard Safeguard REST API calls through SafeguardJava connections.
---

# API Patterns

Use this skill when you need to translate a Safeguard REST endpoint into the Java SDK's
`ISafeguardConnection` calling pattern. The core workflow is always the same: create an
`ISafeguardConnection` with `Safeguard.connect(...)`, choose a `Service` and `Method`,
pass a service-relative URL, then decide whether you need just the body
(`invokeMethod`), a full status/header/body wrapper (`invokeMethodFull`), or CSV output
(`invokeMethodCsv`).

## 1. Service / endpoint enumeration

SafeguardJava routes standard API calls through `com.oneidentity.safeguard.safeguardjava.data.Service`:

| `Service` value | Base path built by `SafeguardConnection` | Typical use |
|---|---|---|
| `Service.Core` | `https://<appliance>/service/core/v<apiVersion>` | Most day-to-day REST work: users, assets, settings, requests |
| `Service.Appliance` | `https://<appliance>/service/appliance/v<apiVersion>` | Appliance-local operations such as backups and network interfaces |
| `Service.Notification` | `https://<appliance>/service/notification/v<apiVersion>` | Anonymous/read-only status-style endpoints |
| `Service.Management` | `https://<address>/service/management/v<apiVersion>` | Management-service-only calls via `GetManagementServiceConnection(...)` |
| `Service.A2A` | not supported through `ISafeguardConnection` | Use `Safeguard.A2A.getContext(...)` instead |

HTTP verbs are limited to `com.oneidentity.safeguard.safeguardjava.data.Method`:

- `Method.Get`
- `Method.Post`
- `Method.Put`
- `Method.Delete`

There is no generic `PATCH` helper in `ISafeguardConnection`.

The SDK default API version is `4` (defined in `Safeguard.java`). Most `connect(...)`
and `getContext(...)` overloads accept `apiVersion` if you need to target an older API.

## 2. URL construction and method dispatch

`SafeguardConnection` builds the service root for you. Pass only the service-relative
path, not the full URL.

```java
String me = connection.invokeMethod(
        Service.Core,
        Method.Get,
        "Me",
        null,
        null,
        null,
        null);
```

Internally, `SafeguardConnection.invokeMethodFull(...)`:

1. validates that `relativeUrl` is not null or empty
2. picks the right `RestClient` from `getClientForService(...)`
3. adds `Authorization: Bearer <token>` unless the connection is anonymous
4. dispatches to `execGET`, `execPOST`, `execPUT`, or `execDELETE`
5. wraps the result in `FullResponse`
6. throws `SafeguardForJavaException` on non-success responses

### Query parameters, headers, and timeout

The full signature is:

```java
String invokeMethod(
        Service service,
        Method method,
        String relativeUrl,
        String body,
        Map<String, String> parameters,
        Map<String, String> additionalHeaders,
        Integer timeout)
```

- `parameters` become query-string values
- `additionalHeaders` are merged into the request headers
- `timeout` is per-request and is measured in milliseconds
- `RestClient.DEFAULT_TIMEOUT_MS` is `100_000` when you pass `null`
- `invokeMethodCsv(...)` forces `Accept: text/csv`
- JSON is the normal default (`RestClient.prepareRequest(...)` adds `Accept: application/json` when needed)

Example with query parameters and an explicit timeout:

```java
Map<String, String> parameters = new HashMap<String, String>();
parameters.put("filter", "Name eq 'Admin'");
parameters.put("fields", "Id,Name");

String users = connection.invokeMethod(
        Service.Core,
        Method.Get,
        "Users",
        null,
        parameters,
        null,
        30000);
```

Use `invokeMethodFull(...)` when the status code or headers matter:

```java
FullResponse response = connection.invokeMethodFull(
        Service.Notification,
        Method.Get,
        "Status",
        null,
        null,
        null,
        null);

System.out.println(response.getStatusCode());
System.out.println(response.getBody());
```

## 3. Authentication context for API calls

Choose the connection factory that matches the credential source you already have:

- `Safeguard.connect(address, accessToken, apiVersion, ignoreSsl)`
- `Safeguard.connect(address, provider, username, password, apiVersion, ignoreSsl)`
- `Safeguard.connectPkce(...)` for PKCE-based interactive auth
- `Safeguard.connect(address, certificatePath, certificatePassword, apiVersion, ignoreSsl)`
- `Safeguard.connect(address, keystorePath, keystorePassword, certificateAlias, apiVersion, ignoreSsl)`
- `Safeguard.connect(address, apiVersion, ignoreSsl)` for anonymous notification calls

Repository examples:

- `Samples/PasswordConnect/.../PasswordConnect.java` uses password auth, then calls `GET Me`
- `Samples/CertificateConnect/.../CertificateConnect.java` uses a PFX/PKCS12 client certificate
- `tests/safeguardjavaclient/.../SafeguardTests.java` exercises `Core`, `Appliance`, `Notification`, and `Management`

If you expect a long-running process, wrap the connection with `Safeguard.Persist(connection)`.
`PersistentSafeguardConnection` checks `getAccessTokenLifetimeRemaining()` before each
`invokeMethod*` call and refreshes expired tokens automatically.

### Management service calls

`Service.Management` is only valid on a management connection:

```java
ISafeguardConnection management = connection.GetManagementServiceConnection(address);
FullResponse info = management.invokeMethodFull(
        Service.Management,
        Method.Get,
        "ApplianceInformation",
        null,
        null,
        null,
        null);
```

Do not try to use `Service.Management` on the original core/appliance/notification connection.

## 4. CRUD examples (standard patterns)

### Read: current user

```java
String me = connection.invokeMethod(
        Service.Core,
        Method.Get,
        "Me",
        null,
        null,
        null,
        null);
```

### Create: add a new asset

This follows the same pattern shown in `README.md` for `POST Assets`.

```java
String assetBody = "{"
        + "\"Name\":\"linux.blue.vas\","
        + "\"NetworkAddress\":\"linux.blue.vas\","
        + "\"Description\":\"A new linux asset\","
        + "\"PlatformId\":188,"
        + "\"AssetPartitionId\":-1"
        + "}";

String created = connection.invokeMethod(
        Service.Core,
        Method.Post,
        "Assets",
        assetBody,
        null,
        null,
        null);
```

### Update: change a setting

`tests/safeguardjavaclient/.../SafeguardJavaClient.java` shows a real `PUT` example:

```java
ObjectNode body = mapper.createObjectNode();
body.put("Value", newValue);

connection.invokeMethod(
        Service.Core,
        Method.Put,
        "Settings/" + URLEncoder.encode(settingName, "UTF-8").replace("+", "%20"),
        mapper.writeValueAsString(body),
        null,
        null,
        null);
```

### Delete: standard pattern

There is no separate delete helper. Use `Method.Delete` with the resource-relative URL:

```java
connection.invokeMethod(
        Service.Core,
        Method.Delete,
        "Assets/123",
        null,
        null,
        null,
        null);
```

The exact path still comes from Swagger for the service/version you are targeting.

### CSV export

If an endpoint supports CSV, call `invokeMethodCsv(...)` rather than manually setting
headers. The SDK adds `Accept: text/csv` for you.

## 5. Error handling and retry behavior

The standard failure modes come directly from `SafeguardConnection` and `RestClient`:

- `ArgumentException` for invalid SDK arguments such as an empty `relativeUrl`
- `ObjectDisposedException` if you call the connection after `dispose()`
- `SafeguardForJavaException("Access token is missing...")` if the connection was logged out
- `SafeguardForJavaException("Unable to connect to web service ...")` when the HTTP call returns `null`
- `SafeguardForJavaException("Error returned from Safeguard API, Error: <status> <body>")` for non-2xx responses

There is **no general automatic retry loop** in `invokeMethod(...)` or `RestClient.exec*()`.
If you need retries for idempotent operations, implement them in the caller.
The built-in resilience feature is token refresh via `Safeguard.Persist(...)`, not HTTP retry.

Practical guidance:

- prefer `invokeMethodFull(...)` when debugging headers or status codes
- log the service, method, relative URL, and sanitized query params
- keep `timeout` explicit for slow endpoints instead of letting hung calls blend together
- clear `char[]` credentials after use, matching the rest of the SDK

## 6. Swagger / OpenAPI integration

The repository `README.md` points to Swagger UI for endpoint discovery:

```text
https://<address>/service/<service>/swagger
```

Map Swagger service names to the SDK like this:

- `core` -> `Service.Core`
- `appliance` -> `Service.Appliance`
- `notification` -> `Service.Notification`
- `a2a` -> `Safeguard.A2A.getContext(...)` and `ISafeguardA2AContext`

When translating Swagger into Java:

1. drop the `/service/<service>/v<version>/` prefix from the path
2. pass only the relative endpoint segment such as `Users`, `Me`, or `Settings/<id>`
3. move query-string fields into the `parameters` map
4. serialize the request body to a JSON string before calling `invokeMethod(...)`
5. use the same `apiVersion` in your connection that you used while inspecting Swagger

If Swagger shows an A2A endpoint, do **not** call it with `Service.A2A`; the SDK rejects
that route and tells you to use the A2A-specific context.

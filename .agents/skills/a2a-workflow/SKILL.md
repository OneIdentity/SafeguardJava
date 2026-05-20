---
name: a2a-workflow
description: Use when working with SafeguardJava application-to-application credential retrieval, brokering, or A2A events.
---

# A2A Workflow

Safeguard Application-to-Application (A2A) is the SDK path for non-interactive
automation that needs privileged credentials without a user login prompt. In
SafeguardJava, A2A is certificate-authenticated, API-key-scoped, and exposed
through `Safeguard.A2A.getContext(...)` plus `ISafeguardA2AContext`. Use it for
service accounts, scheduled jobs, brokers, and other integrations that need to
retrieve or rotate credentials directly from Safeguard.

## 1. What A2A is

The main A2A surface is `com.oneidentity.safeguard.safeguardjava.ISafeguardA2AContext`.
`SafeguardA2AContext` maintains two internal REST clients:

- an A2A client rooted at `https://<appliance>/service/a2a/v<apiVersion>`
- a core client rooted at `https://<appliance>/service/core/v<apiVersion>`

The A2A client is used for credential retrieval and brokering (`Credentials`,
`AccessRequests`), while the core client is used to enumerate `A2ARegistrations`
and their `RetrievableAccounts`.

Important design constraints from the SDK:

- A2A uses certificate auth plus an `Authorization: A2A <apiKey>` header
- `Service.A2A` is **not** valid with `ISafeguardConnection`
- API keys are stored as `char[]` in the public interfaces
- context objects must be cleaned up with `dispose()`

## 2. Setup flow (certificate registration, API key creation)

The repository samples document the expected appliance-side setup:

1. **Trust the certificate chain**
   - `Samples/CertificateConnect/README.md` calls out uploading the root/intermediate CA chain
   - the certificate must be trusted by Safeguard before certificate auth or A2A will work
2. **Register the application / certificate identity**
   - create the application user or mapping that represents the calling service
   - certificate identity can come from a file, keystore alias, in-memory bytes, or a Windows thumbprint
3. **Create A2A registrations**
   - `Samples/A2ARetrievalExample/README.md` calls out configuring retrieval registrations
   - each retrievable credential gets an API key that scopes access to that item
4. **Distribute the client certificate and API key securely**
   - keep certificate passwords, API keys, and retrieved secrets in `char[]`
   - never check PFX/JKS files, passwords, or API keys into the repo

### Choosing a `getContext(...)` overload

`Safeguard.A2A.getContext(...)` supports the same certificate sources the rest of the SDK uses:

- keystore path + alias
- PKCS12 / PFX file path
- in-memory certificate bytes
- Windows certificate thumbprint (Windows only)
- optional `apiVersion`
- either `ignoreSsl` or a custom `HostnameVerifier`

Examples from the actual factories in `Safeguard.java`:

```java
ISafeguardA2AContext fromFile = Safeguard.A2A.getContext(
        appliance,
        certificatePath,
        certificatePassword,
        null,
        true);

ISafeguardA2AContext fromKeystore = Safeguard.A2A.getContext(
        appliance,
        keystorePath,
        keystorePassword,
        certificateAlias,
        null,
        true);
```

Windows thumbprint overloads require `SunMSCAPI` to be available. The SDK throws a
`SafeguardForJavaException` on non-Windows platforms or when the provider is missing.

## 3. Credential retrieval (programmatic access)

### Enumerate retrievable accounts

`ISafeguardA2AContext.getRetrievableAccounts()` first queries `Core/A2ARegistrations`,
then enumerates each registration's `RetrievableAccounts` endpoint. The returned
`IA2ARetrievableAccount` objects include application name, asset/account details,
and the API key as `char[]`.

```java
List<IA2ARetrievableAccount> accounts = a2aContext.getRetrievableAccounts();
for (IA2ARetrievableAccount account : accounts) {
    System.out.println(account.getAssetName() + " -> " + account.getAccountName());
}
```

There is also a filtered form:

```java
List<IA2ARetrievableAccount> accounts =
        a2aContext.getRetrievableAccounts("AccountName eq 'admin'");
```

The filter is passed server-side as the `filter` query parameter on each registration lookup.

### Retrieve a password

This is the path shown in `Samples/A2ARetrievalExample/.../A2ARetrievalExample.java`:

```java
char[] password = a2aContext.retrievePassword(apiKey);
try {
    usePassword(password);
} finally {
    java.util.Arrays.fill(password, '\0');
}
```

Internally, the SDK sends:

- `GET Credentials`
- query parameter `type=Password`
- header `Authorization: A2A <apiKey>`
- client certificate on the TLS connection

### Set a password

The setter method name is capitalized in this SDK:

```java
a2aContext.SetPassword(apiKey, newPassword);
```

That becomes `PUT Credentials/Password` with a JSON string body.

### Retrieve or set an SSH private key

```java
char[] privateKey = a2aContext.retrievePrivateKey(apiKey, KeyFormat.OpenSsh);
a2aContext.SetPrivateKey(apiKey, privateKey, passphrase, KeyFormat.OpenSsh);
```

The getter uses `GET Credentials?type=PrivateKey&keyFormat=<format>`.
The setter uses `PUT Credentials/SshKey` with a serialized `SshKey` payload.

### Retrieve API key secrets

```java
List<IApiKeySecret> secrets = a2aContext.retrieveApiKeySecret(apiKey);
```

This uses `GET Credentials?type=ApiKey` and maps the response into `ApiKeySecret`
objects with `clientId`, `clientSecret`, and related metadata.

## 4. Brokering

SafeguardJava supports brokering through:

- `IBrokeredAccessRequest`
- `BrokeredAccessRequest`
- `BrokeredAccessRequestType`
- `ISafeguardA2AContext.brokerAccessRequest(...)`

The test harness in `tests/safeguardjavaclient/.../SafeguardTests.java` builds a
`BrokeredAccessRequest`, sets `AccountId`, `AssetId`, `ForUserId`, and an access type,
then calls `brokerAccessRequest(...)`.

Minimal pattern:

```java
IBrokeredAccessRequest request = new BrokeredAccessRequest();
request.setForUserId(forUserId);
request.setAssetId(assetId);
request.setAccountId(accountId);
request.setAccessType(BrokeredAccessRequestType.Password);
request.setReasonComment("Created by service broker");

String result = a2aContext.brokerAccessRequest(apiKey, request);
```

What the SDK enforces before sending `POST AccessRequests`:

- either `ForUserId` or `ForUserName` must be set
- either `AssetId` or `AssetName` must be set
- `apiKey` and `accessRequest` cannot be null
- the SDK stamps the request version from the active `apiVersion`

`BrokeredAccessRequest` also exposes optional fields for emergency access, reason
codes, ticket numbers, `RequestedFor`, and day/hour/minute duration values.

## 5. Event listeners / SignalR

A2A supports SignalR listeners through the same `ISafeguardEventListener` interface used
for standard Safeguard events.

### Context-based listeners

From `ISafeguardA2AContext`:

- `getA2AEventListener(char[] apiKey, ISafeguardEventHandler handler)`
- `getA2AEventListener(List<char[]> apiKeys, ISafeguardEventHandler handler)`
- `getPersistentA2AEventListener(char[] apiKey, ISafeguardEventHandler handler)`
- `getPersistentA2AEventListener(List<char[]> apiKeys, ISafeguardEventHandler handler)`

`SafeguardA2AContext` automatically registers these event names on the listener:

- `AssetAccountPasswordUpdated`
- `AssetAccountSshKeyUpdated`
- `AccountApiKeySecretUpdated`

Basic usage:

```java
ISafeguardEventHandler handler = (eventName, eventBody) -> {
    System.out.println(eventName);
    System.out.println(eventBody);
};

ISafeguardEventListener listener =
        a2aContext.getPersistentA2AEventListener(apiKey, handler);
listener.start();
```

### Factory-based listeners

If you do not want to build the context yourself, `Safeguard.A2A.Event` exposes many
`getPersistentA2AEventListener(...)` overloads that accept certificate file, keystore,
thumbprint, or in-memory certificate inputs directly.

### Reconnect behavior

`PersistentSafeguardA2AEventListener` extends `PersistentSafeguardEventListenerBase`.
When the internal SignalR listener disconnects, the base class:

1. disposes the broken listener
2. recreates it from the A2A context
3. re-registers handlers
4. sleeps 5 seconds between failed reconnect attempts

This is the right choice for long-running services.

Non-persistent listeners do **not** recover from long outages.
The interface documentation calls out the 30+ second outage case explicitly.

## 6. Error scenarios and troubleshooting

Common failures are visible directly in the public methods:

- `ObjectDisposedException` if you call the context after `dispose()`
- `ArgumentException` for null `apiKey`, null password/private-key arguments, or an empty API key list
- `SafeguardForJavaException("Unable to connect to web service ...")` when the HTTP client returns null
- `SafeguardForJavaException("Error returned from Safeguard API, Error: <status> <body>")` for non-2xx responses
- `SafeguardForJavaException("You must specify a user...")` or `("You must specify an asset...")` during brokering
- `SafeguardForJavaException("Error parsing JSON response")` or serialization failures when payload conversion breaks
- `SafeguardForJavaException("Missing SunMSCAPI provider...")` for Windows thumbprint usage without the provider
- `SafeguardForJavaException("Not implemented. This function is only available on the Windows platform.")` for thumbprint overloads on non-Windows hosts

Troubleshooting checklist:

1. verify the certificate chain is trusted by Safeguard
2. confirm the certificate maps to the intended application identity
3. confirm the API key belongs to the registration you expect
4. use `getRetrievableAccounts()` to prove what the certificate can actually see
5. switch from a transient listener to a persistent listener if outages matter
6. avoid `ignoreSsl=true` outside lab scenarios
7. clear API keys, passwords, and retrieved secrets from memory when finished

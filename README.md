[![GitHub](https://img.shields.io/github/license/OneIdentity/SafeguardJava.svg)](https://github.com/OneIdentity/SafeguardJava/blob/master/LICENSE)
[![Maven Central](https://img.shields.io/maven-central/v/com.oneidentity.safeguard/safeguardjava)](https://central.sonatype.com/artifact/com.oneidentity.safeguard/safeguardjava)

# SafeguardJava

One Identity Safeguard Web API Java SDK

## Version Compatibility
Note that SafeguardJava 6.8.0 is no longer compatible with versions of Safeguard for Priviledged Passwords less than 6.8.0.  To use SafeguardJava with a version of Safeguard for Priviledged Passwords less than 6.8.0, SafeguardJava 6.7.3 or less must be used.

## Support

One Identity open source projects are supported through [One Identity GitHub issues](https://github.com/OneIdentity/SafeguardJava/issues) and the [One Identity Community](https://www.oneidentity.com/community/). This includes all scripts, plugins, SDKs, modules, code snippets or other solutions. For assistance with any One Identity GitHub project, please raise a new Issue on the [One Identity GitHub project](https://github.com/OneIdentity/SafeguardJava/issues) page. You may also visit the [One Identity Community](https://www.oneidentity.com/community/) to ask questions.  Requests for assistance made through official One Identity Support will be referred back to GitHub and the One Identity Community forums where those requests can benefit all users.

## Default API Update

SafeguardJava will use v4 API by default starting with version 7.0. It is
possible to continue using the v3 API by passing in the apiVersion parameter
when creating a connection or A2A context.

Safeguard for Privileged Passwords 7.X hosts both the v3 and v4 APIs. New coding
projects should target the v4 API, and existing projects can be migrated over time.
Notification will be given to customers many releases in advance of any plans to
remove the v3 API. There are currently no plans to remove the v3 API.

```java
// Use v3 instead of v4
var connection = Safeguard.Connect("safeguard.sample.corp", "local", "Admin", password, 3, true);
var a2aContext = Safeguard.A2A.GetContext("safeguard.sample.corp", thumbprint, 3, true);
```

## Introduction

All functionality in Safeguard is available via the Safeguard API. There is
nothing that can be done in the Safeguard UI that cannot also be performed
using the Safeguard API programmatically.

SafeguardJava is provided to facilitate calling the Safeguard API from Java.
It is meant to remove the complexity of dealing with authentication via
Safeguard's embedded secure token service (STS). It also facilitates
authentication using client certificates, which is the recommended
authentication mechanism for automated processes. The basic usage is to call
`Connect()` to establish a connection to Safeguard, then you can call
`InvokeMethod()` multiple times using the same authenticated connection.

SafeguardJava also provides an easy way to call Safeguard A2A from Java. The
A2A service requires client certificate authentication for retrieving passwords
for application integration. When Safeguard A2A is properly configured,
specified passwords can be retrieved with a single method call without
requiring access request workflow approvals. Safeguard A2A is protected by
API keys and IP restrictions in addition to client certificate authentication.

### A2A Retrievable Accounts

You can list accounts available for A2A credential retrieval, and optionally
filter them using a SCIM-style filter string (Safeguard v2.8+):

```Java
ISafeguardA2AContext a2aContext = Safeguard.A2A.getContext("safeguard.sample.corp", "C:\\client.pfx", password, null, true);

// List all retrievable accounts
List<IA2ARetrievableAccount> accounts = a2aContext.getRetrievableAccounts();

// Filter by account name (server-side SCIM filter)
List<IA2ARetrievableAccount> filtered = a2aContext.getRetrievableAccounts("AccountName eq 'myServiceAccount'");

// Use the API key from a retrievable account to fetch the password
char[] apiKey = accounts.get(0).getApiKey();
char[] password = a2aContext.retrievePassword(apiKey);

a2aContext.dispose();
```

SafeguardJava includes an SDK for listening to Safeguard's powerful, real-time
event notification system. Safeguard provides role-based event notifications
via SignalR to subscribed clients. If a Safeguard user is an Asset Administrator
events related to the creation, modification, or deletion of Assets and Asset
Accounts will be sent to that user. When used with a certificate user, this
provides an opportunity for reacting programmatically to any data modification
in Safeguard. Events are also supported for access request workflow and for
A2A password changes.

> **Note:** The event listener feature requires **Java 9 or later** at runtime
> due to the SignalR client dependency. All other SDK features work on Java 8+.

## Getting Started

### PKCE Authentication (Recommended)

Recent versions of Safeguard for Privileged Passwords **disable the OAuth2 resource
owner password grant (ROG) by default**. The recommended way to connect with a
username and password is PKCE (Proof Key for Code Exchange), which works regardless
of the ROG setting:

```Java
char[] password = GetPasswordSomehow(); // default password is "Admin123"
ISafeguardConnection connection = Safeguard.connectPkce("safeguard.sample.corp", "local", "Admin", password, null, true);
System.out.println(connection.invokeMethod(Service.Core, Method.Get, "Me", null, null, null));
connection.dispose();
```

### Resource Owner Grant Authentication

If the resource owner grant type has been explicitly enabled on your appliance, you
can use `Safeguard.connect()` with a username and password. This will fail with a
400 error if ROG is disabled (the default on recent releases):

```Java
char[] password = GetPasswordSomehow();
ISafeguardConnection connection = Safeguard.connect("safeguard.sample.corp", "local", "Admin", password, null, true);
System.out.println(connection.invokeMethod(Service.Core, Method.Get, "Me", null, null, null));
connection.dispose();
```

### Certificate Authentication

Certificates must be in a PFX (PKCS12) file. Certificate authentication is the
recommended mechanism for automated processes:

```Java
char[] certificatePassword = GetPasswordSomehow();
ISafeguardConnection connection = Safeguard.connect("safeguard.sample.corp", "C:\\cert.pfx", certificatePassword, null, true);
System.out.println(connection.invokeMethod(Service.Core, Method.Get, "Me", null, null, null));
connection.dispose();
```

### Access Token Authentication

If you already have a Safeguard API token, you can use it directly:

```Java
char[] apiToken = GetTokenSomehow();
ISafeguardConnection connection = Safeguard.connect("safeguard.sample.corp", apiToken, null, true);
System.out.println(connection.invokeMethod(Service.Core, Method.Get, "Me", null, null, null));
connection.dispose();
```

### Device Code Authentication

Device Code (OAuth 2.0 Device Authorization Grant, RFC 8628) is designed for
**headless or no-browser callers** such as containers, SSH sessions, CI jobs, and
IoT or otherwise constrained devices. The SDK never opens a browser. Instead, the
caller displays a verification URL and a user code through a required callback, the
user authenticates in their own browser on any device, and the SDK polls until the
login succeeds, is denied, expires, or is cancelled.

```Java
ISafeguardConnection connection = Safeguard.connectDeviceCode(
        "safeguard.sample.corp",
        info -> {
            // Sample display behavior — the library never prints or opens a browser.
            String url = info.getVerificationUriComplete() != null
                    ? info.getVerificationUriComplete() : info.getVerificationUri();
            System.out.println("To sign in, visit " + url + " and enter code " + info.getUserCode());
        },
        null,   // optional DeviceCodeLoginParameters (scope, client id, polling interval, cancel hook)
        null,   // apiVersion
        true);  // ignoreSsl
System.out.println(connection.invokeMethod(Service.Core, Method.Get, "Me", null, null, null));
connection.dispose();
```

The display callback receives only display values (`userCode`, `verificationUri`,
`verificationUriComplete`, `expiresIn`, and `interval`); the internal `device_code`
is never exposed. The polling interval is automatically increased when the appliance
asks the client to slow down, cancellation is caller-driven through
`DeviceCodeLoginParameters.setIsCancelled(...)`, and the deadline is always the
appliance's `expires_in` value.

> **Appliance prerequisite:** the Device Code grant must be enabled on the appliance
> under **Settings → OAuth 2.0 Grant Types** (the API setting
> `Settings/Allowed OAuth2 Grant Types` must include `DeviceCode`). When it is
> disabled, the appliance returns the marker
> `OAuth2 device code grant type is not allowed.` and the SDK throws a clear error
> instructing an administrator to enable it.

A runnable example is in [Samples/DeviceCodeConnect](Samples/DeviceCodeConnect/).

Calling the simple 'Me' endpoint provides information about the currently logged
on user.

## Samples

The [Samples](Samples/) directory contains standalone example projects demonstrating
common SafeguardJava usage patterns:

| Sample | Description |
|--------|-------------|
| [PasswordConnect](Samples/PasswordConnect/) | Connect using username and password, call the API |
| [CertificateConnect](Samples/CertificateConnect/) | Connect using a PKCS12 client certificate file |
| [A2ARetrievalExample](Samples/A2ARetrievalExample/) | Retrieve a credential via Application-to-Application (A2A) |
| [EventListenerExample](Samples/EventListenerExample/) | Subscribe to real-time Safeguard events via SignalR |

Each sample is a self-contained Maven project that can be built and run independently.
See the README in each sample directory for prerequisites and usage instructions.

## About the Safeguard API

The Safeguard API is a REST-based Web API. Safeguard API endpoints are called
using HTTP operators and JSON (or XML) requests and responses. The Safeguard API
is documented using Swagger. You may use Swagger UI to call the API directly or
to read the documentation about URLs, parameters, and payloads.

To access the Swagger UI use a browser to navigate to:
`https://<address>/service/<service>/swagger`

- `<address>` = Safeguard network address
- `<service>` = Safeguard service to use

The Safeguard API is made up of multiple services: core, appliance, notification,
and a2a.

|Service|Description|
|-|-|
|core|Most product functionality is found here. All cluster-wide operations: access request workflow, asset management, policy management, etc.|
|appliance|Appliance specific operations, such as setting IP address, maintenance, backups, support bundles, appliance management|
|notification|Anonymous, unauthenticated operations. This service is available even when the appliance isn't fully online|
|a2a|Application integration specific operations. Fetching passwords, making access requests on behalf of users, etc.|

Each of these services provides a separate Swagger endpoint.

You may use the `Authorize` button at the top of the screen to get an API token
to call the Safeguard API directly using Swagger.

To call the a2a service you should begin by using `Safeguard.A2A.GetContext()` rather than
`Safeguard.Connect()`.

### Examples

Most functionality is in the core service as mentioned above.  The notification service
provides read-only information for status, etc.

#### Anonymous Call for Safeguard Status

```Java
ISafeguardConnection connection = Safeguard.connect("safeguard.sample.corp", null, false);
System.out.println(connection.invokeMethod(Service.Notification, Method.Get, "Status", null, null, null));
```

#### Create a New Linux Asset

```Java
// Assume connection is already made
String jsonBody = new StringBuffer ("{")
        .append("\"Name\" : \"linux.blue.vas\"")
        .append("\"NetworkAddress\ : \"linux.blue.vas\"")
        .append("\"Description\ : \"A new linux asset\"")
        .append("\"PlatformId\" : 188")
        .append("\"AssetPartitionId\" : -1")
        .append("}").toString();

String json = connection.invokeMethod(Service.Core, Method.Post, "Assets", jsonBody, null, null);
System.out.println(json);
```

#### Create a New User and Set the Password

```Java
// Assume connection is already made
String jsonBody = new StringBuffer ("{")
        .append("\"PrimaryAuthenticationProviderId\" : -1")
        .append("\"UserName\ : \"MyNewUser123\"")
        .append("}").toString();

String userJson = connection.invokeMethod(Service.Core, Method.Post, "Users", jsonBody, null, null);

UserObj userObj = new Gson().fromJson(userJson, UserObj.class);
connection.invokeMethod(Service.Core, Method.Put, String.format("Users/%s/Password", userObj.Id), "{\"MyNewUser123\"}");
```

#### Using an SSL Certificate Validation Callback

```Java
ISafeguardConnection connection = Safeguard.connect("safeguard.sample.corp", "local", "myuser", "secret".toCharArray(), new CertificateValidator(), null);

String userJson = connection.invokeMethod(Service.Core, Method.Get, "Users", null, null, null);
```

```Java
package com.mycompany.mypackage;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSession;

public class CertificateValidator implements HostnameVerifier {

    @Override
    public boolean verify(final String s, final SSLSession sslSession) {
        // Do your validation here
        return <true | false>; // Return the result of the validation.
    }

    @Override
    public final String toString() {
        return "CertificateValidator";
    }
}

```

### TLS Certificate Verification and the `ignoreSsl` Flag

Every `Safeguard.connect` / `Safeguard.A2A.GetContext` overload accepts an
`ignoreSsl` (`boolean`) parameter. The SDK pins the minimum TLS version to
**TLS 1.2** in all transports (REST and SignalR), regardless of this flag —
weak TLS versions are never negotiated. What `ignoreSsl` controls is
**X.509 certificate chain validation**, not the TLS version and not hostname
verification on its own.

| Setting | Chain validation | Hostname verification | Recommended use |
|---|---|---|---|
| `ignoreSsl = false` (default) | JVM default truststore | JVM default | **Production.** Trust the appliance via the JVM `cacerts` truststore or a custom truststore. |
| `ignoreSsl = false` + `HostnameVerifier validationCallback` | Caller-supplied callback decides | Caller-supplied | Production with a self-signed or internal-CA appliance whose cert chain is known. |
| `ignoreSsl = true` | **All certificates accepted** | `NoopHostnameVerifier` (any host) | **Development only.** Acceptable for local self-signed test appliances. Never enable in production — it accepts any server certificate, including one presented by an attacker performing a man-in-the-middle. |

**How to do it right in production:**

1. Import the appliance's CA certificate into the JVM truststore
   (`$JAVA_HOME/lib/security/cacerts`) or into a custom truststore passed via
   `-Djavax.net.ssl.trustStore=...`. The default-trust path then validates
   the chain automatically and `ignoreSsl=false` is sufficient.
2. If you cannot modify the truststore, pass a `HostnameVerifier`
   implementation (the `validationCallback` parameter) that pins the
   expected certificate or SPKI fingerprint. Keep `ignoreSsl=false`.
3. Only fall back to `ignoreSsl=true` for ephemeral dev/test environments
   where the appliance presents a self-signed certificate you cannot easily
   add to the truststore. Document the usage and remove it before shipping.

The SDK does **not** emit a runtime warning when `ignoreSsl=true` because
the flag is an explicit opt-in — by the time a caller passes `true`, the
trade-off has already been accepted. The responsibility for production
hardening lies with the integrating application.

### Installation

SafeguardJava is available from [Maven Central](https://central.sonatype.com/artifact/com.oneidentity.safeguard/safeguardjava)
and [GitHub Packages](https://github.com/OneIdentity/SafeguardJava/packages). JARs are also
available for direct download from [GitHub Releases](https://github.com/OneIdentity/SafeguardJava/releases).

**Maven Central** (no additional repository configuration needed):

```xml
<dependency>
    <groupId>com.oneidentity.safeguard</groupId>
    <artifactId>safeguardjava</artifactId>
    <version>7.5.0</version>
</dependency>
```

**GitHub Packages** (requires adding the GitHub Packages repository):

```xml
<repositories>
    <repository>
        <id>github</id>
        <url>https://maven.pkg.github.com/OneIdentity/SafeguardJava</url>
    </repository>
</repositories>

<dependency>
    <groupId>com.oneidentity.safeguard</groupId>
    <artifactId>safeguardjava</artifactId>
    <version>7.5.0</version>
</dependency>
```

### Building SafeguardJava

Building SafeguardJava requires Java JDK 8 or greater and Maven 3.0.5 or greater.
The event listener feature requires Java 9+ at runtime (see note above).

```bash
mvn clean package
```

### Publishing

SafeguardJava is published to Maven Central via the
[Sonatype Central Portal](https://central.sonatype.com) and to GitHub Packages.
Release builds are triggered automatically by the Azure Pipeline when changes are
pushed to `master` or `release-*` branches.

Publishing credentials and signing keys are stored in Azure Key Vault and injected
at build time. To configure publishing for a new environment:

1. Generate a user token at [central.sonatype.com](https://central.sonatype.com)
   and store it as `SonatypeUserToken` / `SonatypeRepositoryPassword` in your
   Azure Key Vault
2. Store a GitHub PAT with `write:packages` scope as `GitHubPackagesToken`
3. Import the GPG signing key and code signing certificate into the Key Vault

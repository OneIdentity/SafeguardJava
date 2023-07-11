[![GitHub](https://img.shields.io/github/license/OneIdentity/SafeguardJava.svg)](https://github.com/OneIdentity/SafeguardJava/blob/master/LICENSE)
[![Maven Central](https://maven-badges.herokuapp.com/maven-central/com.oneidentity.safeguard/safeguardjava/badge.svg)](https://maven-badges.herokuapp.com/maven-central/com.oneidentity.safeguard/safeguardjava)
[![Sonatype Nexus (Snapshots)](https://img.shields.io/nexus/r/https/oss.sonatype.org/com.oneidentity.safeguard/safeguardjava.svg)](https://oss.sonatype.org/content/repositories/releases/com/oneidentity/safeguard/safeguardjava/)
[![Sonatype Nexus (Snapshots)](https://img.shields.io/nexus/s/https/oss.sonatype.org/com.oneidentity.safeguard/safeguardjava.svg)](https://oss.sonatype.org/content/repositories/snapshots/com/oneidentity/safeguard/safeguardjava/)

# SafeguardJava

One Identity Safeguard Web API Java SDK

## Version Compatibility
Note that SafeguardJava 6.8.0 is no longer compatible with versions of Safeguard for Priviledged Passwords less than 6.8.0.  To use SafeguardJava with a version of Safeguard for Priviledged Passwords less than 6.8.0, SafeguardJava 6.7.3 or less must be used.

## Support

One Identity open source projects are supported through [One Identity GitHub issues](https://github.com/OneIdentity/SafeguardJava/issues) and the [One Identity Community](https://www.oneidentity.com/community/). This includes all scripts, plugins, SDKs, modules, code snippets or other solutions. For assistance with any One Identity GitHub project, please raise a new Issue on the [One Identity GitHub project](https://github.com/OneIdentity/SafeguardJava/issues) page. You may also visit the [One Identity Community](https://www.oneidentity.com/community/) to ask questions.  Requests for assistance made through official One Identity Support will be referred back to GitHub and the One Identity Community forums where those requests can benefit all users.

## Default API Update

SafeguardDotNet will use v4 API by default starting with version 7.0. It is
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

SafeguardJava includes an SDK for listening to Safeguard's powerful, real-time
event notification system. Safeguard provides role-based event notifications
via SignalR to subscribed clients. If a Safeguard user is an Asset Administrator
events related to the creation, modification, or deletion of Assets and Asset
Accounts will be sent to that user. When used with a certificate user, this
provides an opportunity for reacting programmatically to any data modification
in Safeguard. Events are also supported for access request workflow and for
A2A password changes.

## Getting Started

A simple code example for calling the Safeguard API:

```Java
char[] password = GetPasswordSomehow(); // default password is "Admin123"
ISafeguardConnection connection = Safeguard.connect("safeguard.sample.corp", "local", "Admin", password, null, true);
System.out.println(connection.invokeMethod(Service.Core, Method.Get, "Me", null, null, null));
connection.dispose();
```

Certificates must be in a PFX (PKCS12) file.

```Java
char[] certificatePassword = GetPasswordSomehow();
ISafeguardConnection connection = Safeguard.connect("safeguard.sample.corp", "C:\\cert.pfx", certificatePassword, null, true);
System.out.println(connection.invokeMethod(Service.Core, Method.Get, "Me", null, null, null));
connection.dispose();
```

A final authentication method that is available is using an existing Safeguard API token.

```Java
char[] apiToken = GetTokenSomehow();
ISafeguardConnection connection = Safeguard.connect("safeguard.sample.corp", apiToken, null, true);
System.out.println(connection.invokeMethod(Service.Core, Method.Get, "Me", null, null, null));
connection.dispose();
```

Calling the simple 'Me' endpoint provides information about the currently logged
on user.

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

### Building SafeguardJava

Building SafeguardJava requires Java JDK 8 or greater and Maven 3.0.5 or greater.  The following dependency should be added to your POM file:

```xml
<dependency>
    <groupId>com.oneidentity.safeguard</groupId>
    <artifactId>safeguardjava</artifactId>
    <version>7.3.0</version>
</dependency>
```

# SafeguardJava Samples

These sample projects demonstrate common usage patterns for the SafeguardJava SDK.
Each sample is a self-contained Maven project that can be built and run independently.

## Prerequisites

- Java JDK 8 or later
- Maven 3.0.5 or later
- Access to a Safeguard for Privileged Passwords appliance

## Samples

| Sample | Description |
|--------|-------------|
| [PasswordConnect](PasswordConnect/) | Connect using username and password, call the API |
| [CertificateConnect](CertificateConnect/) | Connect using a PKCS12 client certificate file |
| [DeviceCodeConnect](DeviceCodeConnect/) | Connect using the OAuth 2.0 Device Code flow (headless, no browser) |
| [A2ARetrievalExample](A2ARetrievalExample/) | Retrieve a credential via Application-to-Application (A2A) |
| [EventListenerExample](EventListenerExample/) | Subscribe to real-time Safeguard events via SignalR |

## Building

Each sample can be built from its own directory:

```bash
cd PasswordConnect
mvn clean package
```

## Running

Each sample is packaged as an executable JAR with dependencies:

```bash
java -jar target/password-connect-1.0-SNAPSHOT-jar-with-dependencies.jar
```

See the README in each sample directory for specific usage instructions.

## Using a Local SDK Build

By default these samples reference SafeguardJava from Maven Central. To use a
local build of the SDK instead, install it to your local Maven repository first:

```bash
# From the SafeguardJava root directory
mvn clean install -Dspotbugs.skip=true
```

Then update the `<version>` in the sample's `pom.xml` to match your local build
(e.g. `8.2.0-SNAPSHOT`).

## Security Note

These samples use `ignoreSsl=true` for convenience. In production, you should
configure proper SSL/TLS certificate validation using a `HostnameVerifier`
callback or by adding the appliance certificate to your Java trust store.

Client certificate authentication (as shown in `CertificateConnect`) is the
recommended approach for automated processes. Certificate enrollment via CSR
ensures that private keys never leave the machine.

package com.oneidentity.safeguard.safeguardjava.restclient;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import org.junit.Test;

/**
 * Regression test: TLS version pinning.
 *
 * <p>Ensures that {@link RestClient} requests an explicit {@code TLSv1.2}
 * {@link SSLContext} rather than the generic {@code "TLS"} protocol string.
 * The generic alias can resolve to TLS 1.0 / 1.1 on misconfigured JVMs;
 * pinning the version at the SDK layer guarantees a TLS 1.2+ handshake
 * regardless of {@code jdk.tls.disabledAlgorithms}.
 *
 * <p>This test exercises the actual private {@code getSSLContext} method via
 * reflection so that any future change of the protocol string is caught.
 */
public class RestClientSSLContextTest {

    private static final String EXPECTED_PROTOCOL = "TLSv1.2";

    /**
     * Verifies that the package-private {@code TLS_PROTOCOL} constant is
     * pinned to TLS 1.2 (the Java 8 baseline minimum) so the source of truth
     * for the handshake version is auditable in one place.
     */
    @Test
    public void tlsProtocolConstantIsPinnedToTls12() throws Exception {
        Field f = RestClient.class.getDeclaredField("TLS_PROTOCOL");
        f.setAccessible(true);
        Object value = f.get(null);
        assertEquals("RestClient.TLS_PROTOCOL must be pinned to TLSv1.2",
                EXPECTED_PROTOCOL, value);
    }

    /**
     * Verifies that the SSLContext produced by RestClient.getSSLContext
     * reports protocol "TLSv1.2". This catches regressions where the
     * constant is correct but the call site reverts to a different string.
     */
    @Test
    public void sslContextProtocolIsTls12() throws Exception {
        RestClient client = new RestClient(
                "https://127.0.0.1:9999",
                true,                  // ignoreSsl — exercises the trust-all path
                (HostnameVerifier) null);

        Method m = RestClient.class.getDeclaredMethod(
                "getSSLContext",
                java.security.KeyStore.class,
                char[].class,
                String.class,
                com.oneidentity.safeguard.safeguardjava.data.CertificateContext.class);
        m.setAccessible(true);
        SSLContext ctx = (SSLContext) m.invoke(client, null, null, null, null);

        assertNotNull("getSSLContext returned null — TLSv1.2 unsupported on this JVM?", ctx);
        assertEquals("RestClient must request TLSv1.2, not generic TLS",
                EXPECTED_PROTOCOL, ctx.getProtocol());
    }
}

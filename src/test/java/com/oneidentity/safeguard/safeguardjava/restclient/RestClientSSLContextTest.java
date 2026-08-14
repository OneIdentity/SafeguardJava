package com.oneidentity.safeguard.safeguardjava.restclient;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import org.junit.Test;

/**
 * Regression test: TLS context wiring for the REST transport.
 *
 * <p>{@link RestClient} builds its {@link SSLContext} with the generic
 * {@code "TLS"} algorithm (so the context is capable of the JVM's highest
 * protocol) and then constrains the <em>enabled</em> protocol versions at the
 * socket-factory layer via {@code TlsConfiguration}. The enabled-version policy
 * (default {@code TLSv1.2} only) is covered by
 * {@link com.oneidentity.safeguard.safeguardjava.TlsConfigurationTest}; this
 * test guards the context algorithm and the private {@code getSSLContext} call
 * site against accidental regressions.
 */
public class RestClientSSLContextTest {

    private static final String EXPECTED_CONTEXT_ALGORITHM = "TLS";

    /**
     * Verifies that the package-private {@code SSLCONTEXT_PROTOCOL} constant is
     * the generic {@code "TLS"} algorithm, keeping the source of truth for the
     * context algorithm auditable in one place.
     */
    @Test
    public void sslContextAlgorithmConstantIsGenericTls() throws Exception {
        Field f = RestClient.class.getDeclaredField("SSLCONTEXT_PROTOCOL");
        f.setAccessible(true);
        Object value = f.get(null);
        assertEquals("RestClient.SSLCONTEXT_PROTOCOL must be the generic \"TLS\" algorithm",
                EXPECTED_CONTEXT_ALGORITHM, value);
    }

    /**
     * Verifies that the SSLContext produced by RestClient.getSSLContext is
     * initialized and reports the generic {@code "TLS"} algorithm. This catches
     * regressions where the call site reverts to a hard-pinned protocol string,
     * which would prevent opt-in TLS 1.3 from ever being negotiated.
     */
    @Test
    public void sslContextReportsGenericTlsAlgorithm() throws Exception {
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

        assertNotNull("getSSLContext returned null — TLS unsupported on this JVM?", ctx);
        assertEquals("RestClient must build a generic TLS context and constrain versions at the socket factory",
                EXPECTED_CONTEXT_ALGORITHM, ctx.getProtocol());
    }
}

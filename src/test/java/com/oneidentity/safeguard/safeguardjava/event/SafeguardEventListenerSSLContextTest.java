package com.oneidentity.safeguard.safeguardjava.event;

import static org.junit.Assert.assertEquals;

import java.lang.reflect.Field;
import org.junit.Test;

/**
 * Regression test: TLS context wiring for the SignalR event listener path.
 *
 * <p>The listener builds its {@code SSLContext} with the generic {@code "TLS"}
 * algorithm and constrains the enabled versions with an OkHttp
 * {@code ConnectionSpec} derived from {@code TlsConfiguration} (default
 * {@code TLSv1.2} only). This test guards the context algorithm constant so the
 * transport cannot silently revert to a hard-pinned protocol string that would
 * block opt-in TLS 1.3.
 *
 * <p>Note: The SignalR dependency may require Java 9+ at class-load time. This
 * test uses Class.forName to detect that situation and skip gracefully rather
 * than failing the build on a Java 8 CI agent.
 */
public class SafeguardEventListenerSSLContextTest {

    private static final String EXPECTED_CONTEXT_ALGORITHM = "TLS";
    private static final String CLASS_NAME =
            "com.oneidentity.safeguard.safeguardjava.event.SafeguardEventListener";

    @Test
    public void sslContextAlgorithmConstantIsGenericTls() throws Exception {
        Class<?> clazz;
        try {
            clazz = Class.forName(CLASS_NAME);
        } catch (UnsupportedClassVersionError e) {
            // SignalR dependency requires Java 9+; skip on Java 8 CI
            System.out.println("SKIP: " + e.getMessage());
            return;
        }
        Field f = clazz.getDeclaredField("SSLCONTEXT_PROTOCOL");
        f.setAccessible(true);
        Object value = f.get(null);
        assertEquals("SafeguardEventListener.SSLCONTEXT_PROTOCOL must be the generic \"TLS\" algorithm",
                EXPECTED_CONTEXT_ALGORITHM, value);
    }
}

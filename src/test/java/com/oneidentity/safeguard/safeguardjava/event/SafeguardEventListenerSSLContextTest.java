package com.oneidentity.safeguard.safeguardjava.event;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.lang.reflect.Field;
import javax.net.ssl.SSLContext;
import org.junit.Test;

/**
 * Regression test: TLS version pinning.
 *
 * <p>Mirror of {@code RestClientSSLContextTest} for the SignalR event
 * listener path: ensures the listener's HTTP client builder is wired with
 * an explicit {@code TLSv1.2} {@link SSLContext}, not the generic
 * {@code "TLS"} alias.
 *
 * <p>Note: The SignalR dependency may require Java 9+ at class-load time.
 * These tests use Class.forName to detect that situation and skip gracefully
 * rather than failing the build on a Java 8 CI agent.
 */
public class SafeguardEventListenerSSLContextTest {

    private static final String EXPECTED_PROTOCOL = "TLSv1.2";
    private static final String CLASS_NAME =
            "com.oneidentity.safeguard.safeguardjava.event.SafeguardEventListener";

    @Test
    public void tlsProtocolConstantIsPinnedToTls12() throws Exception {
        Class<?> clazz;
        try {
            clazz = Class.forName(CLASS_NAME);
        } catch (UnsupportedClassVersionError e) {
            // SignalR dependency requires Java 9+; skip on Java 8 CI
            System.out.println("SKIP: " + e.getMessage());
            return;
        }
        Field f = clazz.getDeclaredField("TLS_PROTOCOL");
        f.setAccessible(true);
        Object value = f.get(null);
        assertEquals("SafeguardEventListener.TLS_PROTOCOL must be pinned to TLSv1.2",
                EXPECTED_PROTOCOL, value);
    }

    @Test
    public void sslContextProtocolIsTls12() throws Exception {
        Class<?> clazz;
        try {
            clazz = Class.forName(CLASS_NAME);
        } catch (UnsupportedClassVersionError e) {
            // SignalR dependency requires Java 9+; skip on Java 8 CI
            System.out.println("SKIP: " + e.getMessage());
            return;
        }
        Field f = clazz.getDeclaredField("TLS_PROTOCOL");
        f.setAccessible(true);
        String protocol = (String) f.get(null);
        SSLContext ctx = SSLContext.getInstance(protocol);
        assertEquals("SafeguardEventListener must request TLSv1.2, not generic TLS",
                EXPECTED_PROTOCOL, ctx.getProtocol());
    }
}

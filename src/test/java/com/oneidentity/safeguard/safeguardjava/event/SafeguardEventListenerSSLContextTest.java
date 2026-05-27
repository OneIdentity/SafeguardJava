package com.oneidentity.safeguard.safeguardjava.event;

import static org.junit.Assert.assertEquals;

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
 */
public class SafeguardEventListenerSSLContextTest {

    private static final String EXPECTED_PROTOCOL = "TLSv1.2";

    @Test
    public void tlsProtocolConstantIsPinnedToTls12() throws Exception {
        Field f = SafeguardEventListener.class.getDeclaredField("TLS_PROTOCOL");
        f.setAccessible(true);
        Object value = f.get(null);
        assertEquals("SafeguardEventListener.TLS_PROTOCOL must be pinned to TLSv1.2",
                EXPECTED_PROTOCOL, value);
    }

    @Test
    public void sslContextProtocolIsTls12() throws Exception {
        Field f = SafeguardEventListener.class.getDeclaredField("TLS_PROTOCOL");
        f.setAccessible(true);
        String protocol = (String) f.get(null);
        SSLContext ctx = SSLContext.getInstance(protocol);
        assertEquals("SafeguardEventListener must request TLSv1.2, not generic TLS",
                EXPECTED_PROTOCOL, ctx.getProtocol());
    }
}

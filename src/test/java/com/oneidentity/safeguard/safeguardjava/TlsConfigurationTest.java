package com.oneidentity.safeguard.safeguardjava;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.fail;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * Unit tests for {@link TlsConfiguration} range resolution, validation, and
 * system-property fallback, plus {@link TlsVersion#fromString(String)} parsing.
 *
 * <p>These verify the core policy of the TLS 1.3 support work: unset =&gt;
 * TLS 1.2 only (preserving legacy behavior and Standard-binding cert-auth), and
 * opt-in expansion to TLS 1.3 via programmatic setters or system properties.
 */
public class TlsConfigurationTest {

    @Before
    @After
    public void reset() {
        TlsConfiguration.setMinTlsVersion(null);
        TlsConfiguration.setMaxTlsVersion(null);
        System.clearProperty(TlsConfiguration.MIN_TLS_VERSION_PROPERTY);
        System.clearProperty(TlsConfiguration.MAX_TLS_VERSION_PROPERTY);
    }

    @Test
    public void defaultIsTls12Only() {
        assertNull(TlsConfiguration.getMinTlsVersion());
        assertNull(TlsConfiguration.getMaxTlsVersion());
        assertArrayEquals(new String[] { "TLSv1.2" },
                TlsConfiguration.resolveEnabledProtocolNames());
    }

    @Test
    public void maxTls13OpensRangeFrom12() {
        TlsConfiguration.setMaxTlsVersion(TlsVersion.TLSv1_3);
        assertArrayEquals(new String[] { "TLSv1.2", "TLSv1.3" },
                TlsConfiguration.resolveEnabledProtocolNames());
    }

    @Test
    public void minTls13RequiresTls13Only() {
        TlsConfiguration.setMinTlsVersion(TlsVersion.TLSv1_3);
        assertArrayEquals(new String[] { "TLSv1.3" },
                TlsConfiguration.resolveEnabledProtocolNames());
    }

    @Test
    public void explicitTls12BoundsPinTo12() {
        TlsConfiguration.setMinTlsVersion(TlsVersion.TLSv1_2);
        TlsConfiguration.setMaxTlsVersion(TlsVersion.TLSv1_2);
        assertArrayEquals(new String[] { "TLSv1.2" },
                TlsConfiguration.resolveEnabledProtocolNames());
    }

    @Test
    public void setterRejectsMinAboveMax() {
        TlsConfiguration.setMaxTlsVersion(TlsVersion.TLSv1_2);
        try {
            TlsConfiguration.setMinTlsVersion(TlsVersion.TLSv1_3);
            fail("Expected IllegalArgumentException for min > max");
        } catch (IllegalArgumentException expected) {
            // ok
        }
    }

    @Test
    public void setterRejectsMaxBelowMin() {
        TlsConfiguration.setMinTlsVersion(TlsVersion.TLSv1_3);
        try {
            TlsConfiguration.setMaxTlsVersion(TlsVersion.TLSv1_2);
            fail("Expected IllegalArgumentException for max < min");
        } catch (IllegalArgumentException expected) {
            // ok
        }
    }

    @Test
    public void systemPropertyFallbackAppliesWhenUnset() {
        System.setProperty(TlsConfiguration.MAX_TLS_VERSION_PROPERTY, "1.3");
        assertArrayEquals(new String[] { "TLSv1.2", "TLSv1.3" },
                TlsConfiguration.resolveEnabledProtocolNames());
    }

    @Test
    public void programmaticSettingOverridesSystemProperty() {
        System.setProperty(TlsConfiguration.MAX_TLS_VERSION_PROPERTY, "1.3");
        TlsConfiguration.setMaxTlsVersion(TlsVersion.TLSv1_2);
        assertArrayEquals(new String[] { "TLSv1.2" },
                TlsConfiguration.resolveEnabledProtocolNames());
    }

    @Test
    public void inconsistentSystemPropertiesThrowOnResolve() {
        System.setProperty(TlsConfiguration.MIN_TLS_VERSION_PROPERTY, "1.3");
        System.setProperty(TlsConfiguration.MAX_TLS_VERSION_PROPERTY, "1.2");
        try {
            TlsConfiguration.resolveEnabledProtocolNames();
            fail("Expected IllegalStateException for min > max via system properties");
        } catch (IllegalStateException expected) {
            // ok
        }
    }

    @Test
    public void fromStringAcceptsMultipleForms() {
        assertEquals(TlsVersion.TLSv1_2, TlsVersion.fromString("TLSv1.2"));
        assertEquals(TlsVersion.TLSv1_2, TlsVersion.fromString("TLSv1_2"));
        assertEquals(TlsVersion.TLSv1_2, TlsVersion.fromString(" 1.2 "));
        assertEquals(TlsVersion.TLSv1_3, TlsVersion.fromString("tlsv1.3"));
        assertEquals(TlsVersion.TLSv1_3, TlsVersion.fromString("1.3"));
        assertNull(TlsVersion.fromString(null));
        assertNull(TlsVersion.fromString(""));
        assertNull(TlsVersion.fromString("TLSv1.1"));
    }
}

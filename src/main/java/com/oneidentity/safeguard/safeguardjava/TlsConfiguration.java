package com.oneidentity.safeguard.safeguardjava;

import java.util.ArrayList;
import java.util.List;

/**
 * Central, process-wide configuration for the TLS protocol versions that
 * SafeguardJava transports (REST clients and the SignalR event listener) are
 * allowed to negotiate.
 *
 * <p><b>Default behavior.</b> When neither a minimum nor a maximum version is
 * configured, SafeguardJava negotiates <b>TLS 1.2 only</b>. This preserves the
 * SDK's historical behavior and, critically, keeps certificate/A2A
 * authentication working on the appliance Standard binding: JSSE cannot present
 * a client certificate in response to a TLS 1.3 post-handshake
 * {@code CertificateRequest} (RFC 8446 &sect;4.6.2), so cert-auth on the
 * Standard binding only succeeds at TLS 1.2.
 *
 * <p><b>Opting into TLS 1.3.</b> Callers may raise the maximum (and/or minimum)
 * version via {@link #setMaxTlsVersion(TlsVersion)} /
 * {@link #setMinTlsVersion(TlsVersion)} (surfaced publicly as
 * {@link Safeguard#setMaxTlsVersion(TlsVersion)} /
 * {@link Safeguard#setMinTlsVersion(TlsVersion)}), or via the
 * {@value #MAX_TLS_VERSION_PROPERTY} / {@value #MIN_TLS_VERSION_PROPERTY} system
 * properties for an interim, no-code-change rollout. Programmatic settings take
 * precedence over system properties.
 *
 * <p>Password/token authentication (which carries no client certificate) can
 * use TLS 1.3 on the Standard binding without issue. Certificate/A2A
 * authentication over TLS 1.3 additionally requires connecting to the appliance
 * Cert SNI hostname, where the certificate is requested in-handshake.
 *
 * <p>This class is thread-safe; the configured versions are held in
 * {@code volatile} fields and read at connection-creation time.
 */
public final class TlsConfiguration {

    /** System property that supplies the minimum TLS version when no value has
     *  been set programmatically. Accepts {@code TLSv1.2}, {@code TLSv1_2},
     *  {@code 1.2}, etc. (see {@link TlsVersion#fromString(String)}). */
    public static final String MIN_TLS_VERSION_PROPERTY = "safeguard.tls.minVersion";

    /** System property that supplies the maximum TLS version when no value has
     *  been set programmatically. Accepts {@code TLSv1.3}, {@code TLSv1_3},
     *  {@code 1.3}, etc. (see {@link TlsVersion#fromString(String)}). */
    public static final String MAX_TLS_VERSION_PROPERTY = "safeguard.tls.maxVersion";

    private static volatile TlsVersion minTlsVersion = null;
    private static volatile TlsVersion maxTlsVersion = null;

    private TlsConfiguration() {
    }

    /**
     * Sets the minimum TLS protocol version the SDK is allowed to negotiate, or
     * {@code null} to defer to the {@value #MIN_TLS_VERSION_PROPERTY} system
     * property (and ultimately the default).
     *
     * @param version the minimum version, or {@code null} to clear.
     * @throws IllegalArgumentException if a maximum is already configured and
     *         {@code version} is higher than it.
     */
    public static void setMinTlsVersion(TlsVersion version) {
        if (version != null && maxTlsVersion != null && version.ordinal() > maxTlsVersion.ordinal()) {
            throw new IllegalArgumentException(String.format(
                    "Minimum TLS version %s cannot be higher than the configured maximum %s",
                    version.getProtocolName(), maxTlsVersion.getProtocolName()));
        }
        minTlsVersion = version;
    }

    /**
     * @return the programmatically configured minimum TLS version, or
     *         {@code null} if unset. Does not reflect the system-property
     *         fallback.
     */
    public static TlsVersion getMinTlsVersion() {
        return minTlsVersion;
    }

    /**
     * Sets the maximum TLS protocol version the SDK is allowed to negotiate, or
     * {@code null} to defer to the {@value #MAX_TLS_VERSION_PROPERTY} system
     * property (and ultimately the default).
     *
     * @param version the maximum version, or {@code null} to clear.
     * @throws IllegalArgumentException if a minimum is already configured and
     *         {@code version} is lower than it.
     */
    public static void setMaxTlsVersion(TlsVersion version) {
        if (version != null && minTlsVersion != null && version.ordinal() < minTlsVersion.ordinal()) {
            throw new IllegalArgumentException(String.format(
                    "Maximum TLS version %s cannot be lower than the configured minimum %s",
                    version.getProtocolName(), minTlsVersion.getProtocolName()));
        }
        maxTlsVersion = version;
    }

    /**
     * @return the programmatically configured maximum TLS version, or
     *         {@code null} if unset. Does not reflect the system-property
     *         fallback.
     */
    public static TlsVersion getMaxTlsVersion() {
        return maxTlsVersion;
    }

    private static TlsVersion effectiveMin() {
        return (minTlsVersion != null) ? minTlsVersion
                : TlsVersion.fromString(System.getProperty(MIN_TLS_VERSION_PROPERTY));
    }

    private static TlsVersion effectiveMax() {
        return (maxTlsVersion != null) ? maxTlsVersion
                : TlsVersion.fromString(System.getProperty(MAX_TLS_VERSION_PROPERTY));
    }

    /**
     * Resolves the ordered set of JSSE protocol names that transports should
     * enable, honoring the configured (or system-property) minimum and maximum
     * bounds.
     *
     * <p>When neither bound is set, this returns {@code ["TLSv1.2"]} (the legacy
     * default). When at least one bound is set, the range spans
     * {@code [min or TLSv1.2 .. max or TLSv1.3]}.
     *
     * @return a non-empty array of JSSE protocol names, lowest version first.
     * @throws IllegalStateException if the resolved minimum is higher than the
     *         resolved maximum (only reachable via inconsistent system
     *         properties).
     */
    public static String[] resolveEnabledProtocolNames() {
        TlsVersion min = effectiveMin();
        TlsVersion max = effectiveMax();

        if (min == null && max == null) {
            return new String[] { TlsVersion.TLSv1_2.getProtocolName() };
        }

        TlsVersion lo = (min != null) ? min : TlsVersion.TLSv1_2;
        TlsVersion hi = (max != null) ? max : TlsVersion.TLSv1_3;
        if (lo.ordinal() > hi.ordinal()) {
            throw new IllegalStateException(String.format(
                    "Invalid TLS version range: minimum %s is higher than maximum %s",
                    lo.getProtocolName(), hi.getProtocolName()));
        }

        List<String> names = new ArrayList<>();
        for (TlsVersion v : TlsVersion.values()) {
            if (v.ordinal() >= lo.ordinal() && v.ordinal() <= hi.ordinal()) {
                names.add(v.getProtocolName());
            }
        }
        return names.toArray(new String[0]);
    }
}

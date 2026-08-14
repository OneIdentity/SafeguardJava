package com.oneidentity.safeguard.safeguardjava;

/**
 * TLS protocol versions that SafeguardJava can be constrained to negotiate.
 *
 * <p>The SDK exposes an opt-in minimum/maximum TLS version bound (see
 * {@link Safeguard#setMinTlsVersion(TlsVersion)} and
 * {@link Safeguard#setMaxTlsVersion(TlsVersion)}). Only the two versions
 * relevant to modern Safeguard appliances are offered; TLS 1.0 and 1.1 are
 * never enabled by the SDK.
 *
 * <p>The enum declaration order (lowest to highest) is significant: the range
 * resolver in {@link TlsConfiguration} relies on {@link #ordinal()} to compare
 * versions.
 */
public enum TlsVersion {

    /** TLS 1.2 &mdash; the SafeguardJava default and the only version that
     *  supports certificate/A2A authentication on the Standard binding. */
    TLSv1_2("TLSv1.2"),

    /** TLS 1.3 &mdash; opt-in. Certificate/A2A authentication over TLS 1.3
     *  requires connecting to the appliance Cert SNI hostname because JSSE
     *  cannot present a client certificate post-handshake. */
    TLSv1_3("TLSv1.3");

    private final String protocolName;

    TlsVersion(String protocolName) {
        this.protocolName = protocolName;
    }

    /**
     * The JSSE protocol name for this version (e.g. {@code "TLSv1.2"}), as used
     * by {@code SSLSocket.setEnabledProtocols(String[])}.
     *
     * @return the JSSE protocol name.
     */
    public String getProtocolName() {
        return protocolName;
    }

    /**
     * Parses a {@link TlsVersion} from a string, accepting the enum name
     * ({@code TLSv1_2}), the JSSE protocol name ({@code TLSv1.2}), or a bare
     * version number ({@code 1.2}). Parsing is case-insensitive and tolerant of
     * surrounding whitespace. This is used to resolve the
     * {@code safeguard.tls.minVersion} / {@code safeguard.tls.maxVersion} system
     * properties.
     *
     * @param value the value to parse; may be {@code null}.
     * @return the matching {@link TlsVersion}, or {@code null} when
     *         {@code value} is {@code null}, blank, or unrecognized.
     */
    public static TlsVersion fromString(String value) {
        if (value == null) {
            return null;
        }
        String v = value.trim();
        if (v.isEmpty()) {
            return null;
        }
        for (TlsVersion t : values()) {
            if (t.name().equalsIgnoreCase(v)
                    || t.protocolName.equalsIgnoreCase(v)
                    || t.protocolName.substring("TLSv".length()).equalsIgnoreCase(v)) {
                return t;
            }
        }
        return null;
    }
}

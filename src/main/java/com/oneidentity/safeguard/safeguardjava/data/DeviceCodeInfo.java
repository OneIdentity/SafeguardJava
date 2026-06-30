package com.oneidentity.safeguard.safeguardjava.data;

/**
 * Carries the OAuth 2.0 Device Authorization Grant (RFC 8628) values that are
 * intended to be shown to the user so that they can complete authentication in
 * a browser on any device.
 * <p>
 * This object is passed to a caller-provided
 * {@link com.oneidentity.safeguard.safeguardjava.IDeviceCodeDisplayCallback}.
 * The raw {@code device_code} that the library uses internally to poll for the
 * token is deliberately <b>not</b> exposed here.
 */
public class DeviceCodeInfo {

    private final String userCode;
    private final String verificationUri;
    private final String verificationUriComplete;
    private final int expiresIn;
    private final Integer interval;

    /**
     * Creates a new device code info object.
     *
     * @param userCode The user code the end user must enter (RFC 8628 {@code user_code}).
     * @param verificationUri The verification URI the end user should visit ({@code verification_uri}).
     * @param verificationUriComplete The verification URI with the user code embedded
     *        ({@code verification_uri_complete}); may be {@code null} if not supplied.
     * @param expiresIn The number of seconds until the device code expires ({@code expires_in}).
     * @param interval The minimum polling interval in seconds suggested by the appliance
     *        ({@code interval}); may be {@code null} if not supplied.
     */
    public DeviceCodeInfo(String userCode, String verificationUri, String verificationUriComplete,
            int expiresIn, Integer interval) {
        this.userCode = userCode;
        this.verificationUri = verificationUri;
        this.verificationUriComplete = verificationUriComplete;
        this.expiresIn = expiresIn;
        this.interval = interval;
    }

    /**
     * Gets the user code the end user must enter to authorize the device.
     *
     * @return The user code.
     */
    public String getUserCode() {
        return userCode;
    }

    /**
     * Gets the verification URI the end user should visit in a browser.
     *
     * @return The verification URI.
     */
    public String getVerificationUri() {
        return verificationUri;
    }

    /**
     * Gets the verification URI with the user code already embedded, when the
     * appliance provides it. Prefer displaying this value when present.
     *
     * @return The complete verification URI, or {@code null} if not supplied.
     */
    public String getVerificationUriComplete() {
        return verificationUriComplete;
    }

    /**
     * Gets the number of seconds until the device code expires.
     *
     * @return The lifetime of the device code in seconds.
     */
    public int getExpiresIn() {
        return expiresIn;
    }

    /**
     * Gets the minimum polling interval suggested by the appliance, in seconds.
     *
     * @return The suggested interval, or {@code null} if not supplied.
     */
    public Integer getInterval() {
        return interval;
    }
}

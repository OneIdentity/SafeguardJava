package com.oneidentity.safeguard.safeguardjava.exceptions;

/**
 * Thrown when an HTTP response body exceeds the SDK's configured size cap.
 *
 * <p>This is a defensive limit against a misbehaving or malicious appliance
 * returning multi-gigabyte responses that would exhaust client memory if
 * fully buffered. Normal Safeguard API responses are well under the default
 * cap (10 MB); legitimate large transfers must use the streaming download
 * API ({@code StreamResponse} / {@code StreamingRequest}), which does not
 * buffer the body in memory and is therefore not subject to this cap.
 */
public class ResponseTooLargeException extends SafeguardForJavaException {

    private static final long serialVersionUID = 1L;

    public ResponseTooLargeException(String msg) {
        super(msg);
    }

    public ResponseTooLargeException(long observed, long limit) {
        super(String.format(
                "Response body of %d bytes exceeds the configured cap of %d bytes",
                observed, limit));
    }
}

package com.oneidentity.safeguard.safeguardjava.authentication;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.oneidentity.safeguard.safeguardjava.IDeviceCodeDisplayCallback;
import com.oneidentity.safeguard.safeguardjava.Utils;
import com.oneidentity.safeguard.safeguardjava.data.DeviceCodeInfo;
import com.oneidentity.safeguard.safeguardjava.data.JsonObject;
import com.oneidentity.safeguard.safeguardjava.exceptions.ArgumentException;
import com.oneidentity.safeguard.safeguardjava.exceptions.ObjectDisposedException;
import com.oneidentity.safeguard.safeguardjava.exceptions.SafeguardForJavaException;
import java.util.Locale;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import javax.net.ssl.HostnameVerifier;
import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;

/**
 * Authenticator that implements the OAuth 2.0 Device Authorization Grant
 * (RFC 8628) against the Safeguard rSTS.
 * <p>
 * This authenticator only performs RFC 8628 token <i>acquisition</i>: it
 * requests a device code, hands the verification URL and user code to a
 * caller-provided {@link IDeviceCodeDisplayCallback}, and then polls the rSTS
 * token endpoint until the user authorizes (or the flow is denied, expires, or
 * is cancelled). The resulting rSTS token is exchanged for a Safeguard
 * {@code UserToken} by the inherited {@link AuthenticatorBase#refreshAccessToken()}.
 * <p>
 * The library never opens a browser, prints, or logs the verification values,
 * and never exposes the raw {@code device_code}.
 */
public class DeviceCodeAuthenticator extends AuthenticatorBase {

    private static final Logger logger = LoggerFactory.getLogger(DeviceCodeAuthenticator.class);

    private static final String DEVICE_LOGIN_PATH = "oauth2/DeviceLogin";
    private static final String TOKEN_PATH = "oauth2/token";
    private static final String DEVICE_CODE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:device_code";

    // Marker (case-insensitive) emitted by the appliance when the Device Code grant is disabled.
    // The disabled response body is HTML, so it is matched by substring rather than JSON-parsed.
    private static final String DISABLED_GRANT_MARKER = "device code grant type is not allowed";

    private static final int SLOW_DOWN_INCREMENT_SECONDS = 5;

    private boolean disposed;

    private final IDeviceCodeDisplayCallback displayCallback;
    private final DeviceCodeLoginParameters parameters;

    private int currentPollingIntervalSeconds;

    /**
     * Creates a Device Code authenticator.
     *
     * @param networkAddress Network address of Safeguard appliance.
     * @param displayCallback Required callback used to display the verification URL and user code.
     * @param parameters Optional Device Code parameters; defaults are used when null.
     * @param apiVersion Target API version.
     * @param ignoreSsl Whether to ignore SSL certificate validation.
     * @param validationCallback Optional hostname verifier callback.
     * @throws ArgumentException If the display callback is null.
     */
    public DeviceCodeAuthenticator(String networkAddress, IDeviceCodeDisplayCallback displayCallback,
            DeviceCodeLoginParameters parameters, int apiVersion, boolean ignoreSsl,
            HostnameVerifier validationCallback) throws ArgumentException {
        super(networkAddress, apiVersion, ignoreSsl, validationCallback);
        if (displayCallback == null) {
            throw new ArgumentException("The displayCallback parameter can not be null");
        }
        this.displayCallback = displayCallback;
        this.parameters = parameters == null ? new DeviceCodeLoginParameters() : parameters;
        this.currentPollingIntervalSeconds = this.parameters.getPollingIntervalSeconds();
    }

    @Override
    public String getId() {
        return "DeviceCode";
    }

    @Override
    protected char[] getRstsTokenInternal() throws ObjectDisposedException, SafeguardForJavaException {
        if (disposed) {
            throw new ObjectDisposedException("DeviceCodeAuthenticator");
        }

        String clientId = parameters.getClientId();
        String scope = parameters.getScope();

        // Step 1 - Request device code.
        RstsResponse deviceResponse = requestDeviceCode(clientId, scope);

        // Step 2 - Detect a disabled grant reactively (non-200 HTML; do not JSON-parse).
        if (deviceResponse.getStatusCode() != 200) {
            String body = deviceResponse.getBody() == null ? "" : deviceResponse.getBody();
            if (body.toLowerCase(Locale.ROOT).contains(DISABLED_GRANT_MARKER)) {
                throw new SafeguardForJavaException("The OAuth 2.0 Device Code grant type is not enabled on this "
                        + "Safeguard appliance. An administrator must enable it under "
                        + "Settings -> OAuth 2.0 Grant Types (API setting 'Settings/Allowed OAuth2 Grant Types' "
                        + "must include 'DeviceCode').");
            }
            throw new SafeguardForJavaException(String.format(
                    "Error requesting device code from RSTS, Error: %d %s", deviceResponse.getStatusCode(), body));
        }

        // Parse the device authorization response only on HTTP 200.
        JsonNode node = parseJson(deviceResponse.getBody());
        String deviceCode = requireString(node, "device_code");
        String userCode = requireString(node, "user_code");
        String verificationUri = requireString(node, "verification_uri");
        int expiresIn = requireInt(node, "expires_in");
        String verificationUriComplete = optionalString(node, "verification_uri_complete");
        Integer interval = optionalInt(node, "interval");

        // Step 3 - Display (the device_code is never exposed to the caller).
        DeviceCodeInfo info = new DeviceCodeInfo(userCode, verificationUri, verificationUriComplete, expiresIn, interval);
        displayCallback.display(info);

        // Step 4 - Poll until success, denial, expiry, deadline, or cancellation.
        return pollForToken(clientId, deviceCode, expiresIn);
    }

    private char[] pollForToken(String clientId, String deviceCode, int expiresIn)
            throws SafeguardForJavaException {

        long deadlineMillis = monotonicMillis() + (long) expiresIn * 1000L;
        currentPollingIntervalSeconds = parameters.getPollingIntervalSeconds();

        while (true) {
            if (isCancelled()) {
                throw new SafeguardForJavaException("Device code authentication was cancelled");
            }
            if (monotonicMillis() >= deadlineMillis) {
                throw new SafeguardForJavaException(
                        "Device code authentication timed out before the user completed authorization");
            }

            waitInterval(currentPollingIntervalSeconds);

            if (isCancelled()) {
                throw new SafeguardForJavaException("Device code authentication was cancelled");
            }

            RstsResponse response = requestToken(clientId, deviceCode);

            if (response.getStatusCode() == 200) {
                JsonNode tokenNode = parseJson(response.getBody());
                JsonNode accessToken = tokenNode.get("access_token");
                if (accessToken == null || accessToken.isNull() || Utils.isNullOrEmpty(accessToken.asText())) {
                    throw new SafeguardForJavaException(
                            "Device code token response did not contain an access_token");
                }
                return accessToken.asText().toCharArray();
            }

            String error = extractError(response.getBody());
            if ("authorization_pending".equalsIgnoreCase(error)) {
                logger.debug("Device code authorization pending");
            } else if ("slow_down".equalsIgnoreCase(error)) {
                currentPollingIntervalSeconds += SLOW_DOWN_INCREMENT_SECONDS;
                logger.debug("Device code polling slowed down to {} seconds", currentPollingIntervalSeconds);
            } else if ("access_denied".equalsIgnoreCase(error)) {
                throw new SafeguardForJavaException("Device code authentication was denied by the user");
            } else if ("expired_token".equalsIgnoreCase(error)) {
                throw new SafeguardForJavaException(
                        "The device code expired before the user completed authorization");
            } else {
                throw new SafeguardForJavaException(String.format(
                        "Error polling for device code token, Error: %d %s",
                        response.getStatusCode(), response.getBody()));
            }
        }
    }

    private boolean isCancelled() {
        try {
            Boolean cancelled = parameters.getIsCancelled().get();
            return Boolean.TRUE.equals(cancelled);
        } catch (RuntimeException ex) {
            logger.warn("Cancel hook threw an exception; treating as not cancelled", ex);
            return false;
        }
    }

    /**
     * Requests a device code from the rSTS. Exposed for testability.
     *
     * @param clientId OAuth client id (may be empty).
     * @param scope Scope selecting the authentication provider.
     * @return The raw rSTS response.
     * @throws SafeguardForJavaException If the rSTS cannot be reached.
     */
    protected RstsResponse requestDeviceCode(String clientId, String scope) throws SafeguardForJavaException {
        final String body = new StringBuilder("{")
                .append(Utils.toJsonString("client_id", clientId, false))
                .append(Utils.toJsonString("scope", scope, true))
                .append("}").toString();

        CloseableHttpResponse response = rstsClient.execPOST(DEVICE_LOGIN_PATH, null, null, null, jsonBody(body));
        if (response == null) {
            throw new SafeguardForJavaException(
                    String.format("Unable to connect to RSTS service %s", rstsClient.getBaseURL()));
        }
        return new RstsResponse(response.getCode(), Utils.getResponse(response));
    }

    /**
     * Polls the rSTS token endpoint with the device code. Exposed for testability.
     *
     * @param clientId OAuth client id (may be empty).
     * @param deviceCode The device code returned from the device authorization request.
     * @return The raw rSTS response.
     * @throws SafeguardForJavaException If the rSTS cannot be reached.
     */
    protected RstsResponse requestToken(String clientId, String deviceCode) throws SafeguardForJavaException {
        final String body = new StringBuilder("{")
                .append(Utils.toJsonString("grant_type", DEVICE_CODE_GRANT_TYPE, false))
                .append(Utils.toJsonString("device_code", jsonEscape(deviceCode), true))
                .append(Utils.toJsonString("client_id", clientId, true))
                .append("}").toString();

        CloseableHttpResponse response = rstsClient.execPOST(TOKEN_PATH, null, null, null, jsonBody(body));
        if (response == null) {
            throw new SafeguardForJavaException(
                    String.format("Unable to connect to RSTS service %s", rstsClient.getBaseURL()));
        }
        return new RstsResponse(response.getCode(), Utils.getResponse(response));
    }

    /**
     * Waits before the next poll attempt. Sleeps in one-second increments so the
     * cancel hook can abort promptly during a wait. Exposed for testability.
     *
     * @param seconds The number of seconds to wait.
     */
    protected void waitInterval(int seconds) {
        for (int i = 0; i < seconds; i++) {
            if (isCancelled()) {
                return;
            }
            sleepMillis(1000L);
        }
    }

    /**
     * Sleeps for the given number of milliseconds. Exposed for testability.
     *
     * @param millis The number of milliseconds to sleep.
     */
    protected void sleepMillis(long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
        }
    }

    /**
     * Returns a monotonic time source in milliseconds used to enforce the
     * {@code expires_in} deadline. Exposed for testability.
     *
     * @return A monotonic timestamp in milliseconds.
     */
    protected long monotonicMillis() {
        return System.nanoTime() / 1_000_000L;
    }

    int getCurrentPollingIntervalSeconds() {
        return currentPollingIntervalSeconds;
    }

    private static JsonObject jsonBody(final String json) {
        return () -> json;
    }

    private static String jsonEscape(String value) {
        if (value == null) {
            return "";
        }
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private JsonNode parseJson(String body) throws SafeguardForJavaException {
        try {
            JsonNode node = new ObjectMapper().readTree(body == null ? "" : body);
            if (node == null || node.isNull()) {
                throw new SafeguardForJavaException("Empty or invalid JSON response from RSTS");
            }
            return node;
        } catch (SafeguardForJavaException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new SafeguardForJavaException("Unable to parse JSON response from RSTS", ex);
        }
    }

    private static String extractError(String body) {
        try {
            JsonNode node = new ObjectMapper().readTree(body == null ? "" : body);
            if (node != null && node.has("error")) {
                return node.get("error").asText();
            }
        } catch (java.io.IOException ex) {
            // Fall through; an unparseable body yields no error code.
        }
        return "";
    }

    private static String requireString(JsonNode node, String field) throws SafeguardForJavaException {
        JsonNode value = node.get(field);
        if (value == null || value.isNull() || Utils.isNullOrEmpty(value.asText())) {
            throw new SafeguardForJavaException(
                    String.format("Device authorization response is missing required field '%s'", field));
        }
        return value.asText();
    }

    private static int requireInt(JsonNode node, String field) throws SafeguardForJavaException {
        JsonNode value = node.get(field);
        if (value == null || value.isNull() || !value.canConvertToInt()) {
            throw new SafeguardForJavaException(
                    String.format("Device authorization response is missing required field '%s'", field));
        }
        return value.asInt();
    }

    private static String optionalString(JsonNode node, String field) {
        JsonNode value = node.get(field);
        if (value == null || value.isNull() || Utils.isNullOrEmpty(value.asText())) {
            return null;
        }
        return value.asText();
    }

    private static Integer optionalInt(JsonNode node, String field) {
        JsonNode value = node.get(field);
        if (value == null || value.isNull() || !value.canConvertToInt()) {
            return null;
        }
        return value.asInt();
    }

    @Override
    public Object cloneObject() throws SafeguardForJavaException {
        try {
            DeviceCodeAuthenticator auth = new DeviceCodeAuthenticator(getNetworkAddress(), displayCallback,
                    parameters, getApiVersion(), isIgnoreSsl(), getValidationCallback());
            auth.accessToken = this.accessToken == null ? null : this.accessToken.clone();
            return auth;
        } catch (ArgumentException ex) {
            logger.error("Exception occurred", ex);
        }
        return null;
    }

    @Override
    public void dispose() {
        super.dispose();
        disposed = true;
    }

    @Override
    protected void finalize() throws Throwable {
        try {
            disposed = true;
        } finally {
            super.finalize();
        }
    }

    /**
     * Minimal holder for an rSTS HTTP response (status code and body). Used to
     * decouple the Device Code protocol logic from the HTTP transport so the
     * authenticator can be unit tested without live network calls.
     */
    protected static final class RstsResponse {

        private final int statusCode;
        private final String body;

        /**
         * Creates a response holder.
         *
         * @param statusCode HTTP status code.
         * @param body Response body.
         */
        public RstsResponse(int statusCode, String body) {
            this.statusCode = statusCode;
            this.body = body;
        }

        /**
         * Gets the HTTP status code.
         *
         * @return The status code.
         */
        public int getStatusCode() {
            return statusCode;
        }

        /**
         * Gets the response body.
         *
         * @return The response body.
         */
        public String getBody() {
            return body;
        }
    }
}

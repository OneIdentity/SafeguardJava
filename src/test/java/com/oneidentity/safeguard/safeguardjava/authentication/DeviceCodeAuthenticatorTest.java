package com.oneidentity.safeguard.safeguardjava.authentication;

import com.oneidentity.safeguard.safeguardjava.IDeviceCodeDisplayCallback;
import com.oneidentity.safeguard.safeguardjava.Safeguard;
import com.oneidentity.safeguard.safeguardjava.data.DeviceCodeInfo;
import com.oneidentity.safeguard.safeguardjava.data.JsonObject;
import com.oneidentity.safeguard.safeguardjava.exceptions.ArgumentException;
import com.oneidentity.safeguard.safeguardjava.exceptions.SafeguardForJavaException;
import com.oneidentity.safeguard.safeguardjava.restclient.RestClient;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import javax.net.ssl.HostnameVerifier;
import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.io.entity.StringEntity;
import org.apache.hc.core5.http.message.BasicClassicHttpResponse;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import org.junit.Test;

/**
 * Unit tests for the Device Code (OAuth 2.0 Device Authorization Grant, RFC 8628)
 * authenticator. The rSTS HTTP transport and the sleeper/clock are overridden via
 * protected seams so the protocol logic can be verified without a live appliance.
 */
public class DeviceCodeAuthenticatorTest {

    private static final String DEVICE_LOGIN_JSON =
            "{\"device_code\":\"DEV-CODE-SECRET\",\"user_code\":\"WXYZ-1234\","
            + "\"verification_uri\":\"https://appliance/RSTS/UserLogin\","
            + "\"verification_uri_complete\":\"https://appliance/RSTS/UserLogin?user_code=WXYZ-1234\","
            + "\"expires_in\":300,\"interval\":5}";

    private static DeviceCodeLoginParameters defaultParams() {
        return new DeviceCodeLoginParameters();
    }

    private static IDeviceCodeDisplayCallback noopCallback() {
        return info -> { };
    }

    // ----- Disabled-grant detection -----

    @Test
    public void disabledGrantHtmlIsDetectedWithoutJsonParsing() {
        String html = "<html><body>OAuth2 Device Code grant type is not allowed.</body></html>";
        TestAuthenticator auth = newAuth(noopCallback(), defaultParams());
        auth.deviceResponse = response(400, html);

        try {
            auth.invokeGetRstsToken();
            fail("Expected a disabled-grant exception");
        } catch (SafeguardForJavaException ex) {
            String msg = ex.getMessage();
            assertTrue("Message should instruct to enable Device Code: " + msg,
                    msg.contains("Device Code grant type is not enabled"));
            assertTrue("Message should reference the grant types setting: " + msg,
                    msg.contains("Allowed OAuth2 Grant Types"));
            // The HTML error path must not have produced a JSON parse error.
            assertTrue("Should not surface a JSON parse error: " + msg,
                    !msg.toLowerCase().contains("parse json"));
        }
        assertEquals("Disabled grant must short-circuit before any token poll", 0, auth.requestTokenCalls);
    }

    @Test
    public void nonDisabledErrorFromDeviceLoginThrowsGenericError() {
        TestAuthenticator auth = newAuth(noopCallback(), defaultParams());
        auth.deviceResponse = response(503, "Service Unavailable");

        try {
            auth.invokeGetRstsToken();
            fail("Expected a generic error");
        } catch (SafeguardForJavaException ex) {
            assertTrue(ex.getMessage().contains("Error requesting device code"));
        }
    }

    // ----- Display callback -----

    @Test
    public void displayCallbackReceivesDisplayValuesOnly() throws Exception {
        final List<DeviceCodeInfo> captured = new ArrayList<>();
        TestAuthenticator auth = newAuth(captured::add, defaultParams());
        auth.deviceResponse = response(200, DEVICE_LOGIN_JSON);
        auth.tokenResponses.add(response(200, "{\"access_token\":\"RSTS-TOKEN\"}"));

        auth.invokeGetRstsToken();

        assertEquals(1, captured.size());
        DeviceCodeInfo info = captured.get(0);
        assertEquals("WXYZ-1234", info.getUserCode());
        assertEquals("https://appliance/RSTS/UserLogin", info.getVerificationUri());
        assertEquals("https://appliance/RSTS/UserLogin?user_code=WXYZ-1234", info.getVerificationUriComplete());
        assertEquals(300, info.getExpiresIn());
        assertEquals(Integer.valueOf(5), info.getInterval());
        // DeviceCodeInfo deliberately exposes no device_code accessor (compile-time guarantee).
    }

    @Test
    public void optionalDeviceLoginFieldsMayBeAbsent() throws Exception {
        final List<DeviceCodeInfo> captured = new ArrayList<>();
        TestAuthenticator auth = newAuth(captured::add, defaultParams());
        auth.deviceResponse = response(200, "{\"device_code\":\"D\",\"user_code\":\"U\","
                + "\"verification_uri\":\"https://v\",\"expires_in\":120}");
        auth.tokenResponses.add(response(200, "{\"access_token\":\"RSTS-TOKEN\"}"));

        auth.invokeGetRstsToken();

        DeviceCodeInfo info = captured.get(0);
        assertNull(info.getVerificationUriComplete());
        assertNull(info.getInterval());
        assertEquals(120, info.getExpiresIn());
    }

    @Test
    public void missingRequiredDeviceLoginFieldThrows() {
        TestAuthenticator auth = newAuth(noopCallback(), defaultParams());
        auth.deviceResponse = response(200, "{\"user_code\":\"U\",\"verification_uri\":\"https://v\",\"expires_in\":120}");

        try {
            auth.invokeGetRstsToken();
            fail("Expected missing device_code error");
        } catch (SafeguardForJavaException ex) {
            assertTrue(ex.getMessage().contains("device_code"));
        }
    }

    // ----- Poll-loop transitions -----

    @Test
    public void authorizationPendingThenSuccessReturnsAccessToken() throws Exception {
        TestAuthenticator auth = newAuth(noopCallback(), defaultParams());
        auth.deviceResponse = response(200, DEVICE_LOGIN_JSON);
        auth.tokenResponses.add(response(400, "{\"error\":\"authorization_pending\"}"));
        auth.tokenResponses.add(response(400, "{\"error\":\"authorization_pending\"}"));
        auth.tokenResponses.add(response(200, "{\"access_token\":\"RSTS-FINAL\"}"));

        char[] token = auth.invokeGetRstsToken();

        assertEquals("RSTS-FINAL", new String(token));
        assertEquals(3, auth.requestTokenCalls);
    }

    @Test
    public void slowDownIncreasesPollingIntervalByFiveSeconds() throws Exception {
        TestAuthenticator auth = newAuth(noopCallback(), defaultParams());
        auth.deviceResponse = response(200, DEVICE_LOGIN_JSON);
        auth.tokenResponses.add(response(400, "{\"error\":\"slow_down\"}"));
        auth.tokenResponses.add(response(200, "{\"access_token\":\"RSTS-FINAL\"}"));

        char[] token = auth.invokeGetRstsToken();

        assertEquals("RSTS-FINAL", new String(token));
        // Default polling interval is 5; after one slow_down it must be 10.
        assertEquals(10, auth.getCurrentPollingIntervalSeconds());
    }

    // ----- Terminal failures -----

    @Test
    public void accessDeniedThrows() {
        TestAuthenticator auth = newAuth(noopCallback(), defaultParams());
        auth.deviceResponse = response(200, DEVICE_LOGIN_JSON);
        auth.tokenResponses.add(response(400, "{\"error\":\"access_denied\"}"));

        try {
            auth.invokeGetRstsToken();
            fail("Expected access_denied error");
        } catch (SafeguardForJavaException ex) {
            assertTrue(ex.getMessage().toLowerCase().contains("denied"));
        }
    }

    @Test
    public void expiredTokenThrows() {
        TestAuthenticator auth = newAuth(noopCallback(), defaultParams());
        auth.deviceResponse = response(200, DEVICE_LOGIN_JSON);
        auth.tokenResponses.add(response(400, "{\"error\":\"expired_token\"}"));

        try {
            auth.invokeGetRstsToken();
            fail("Expected expired_token error");
        } catch (SafeguardForJavaException ex) {
            assertTrue(ex.getMessage().toLowerCase().contains("expired"));
        }
    }

    @Test
    public void deadlineExceededAtExpiresInCutoffThrows() {
        TestAuthenticator auth = newAuth(noopCallback(), defaultParams());
        auth.deviceResponse = response(200, DEVICE_LOGIN_JSON);
        // First clock read computes the deadline (0 + 300s); the next read jumps past it.
        auth.clockValues.add(0L);
        auth.clockValues.add(300_000L + 1L);

        try {
            auth.invokeGetRstsToken();
            fail("Expected a timeout/deadline error");
        } catch (SafeguardForJavaException ex) {
            assertTrue(ex.getMessage().toLowerCase().contains("timed out"));
        }
        assertEquals("Deadline must be enforced before polling", 0, auth.requestTokenCalls);
    }

    // ----- Cancel hook -----

    @Test
    public void cancelHookAbortsBeforePolling() {
        DeviceCodeLoginParameters params = new DeviceCodeLoginParameters();
        params.setIsCancelled(() -> Boolean.TRUE);
        TestAuthenticator auth = newAuth(noopCallback(), params);
        auth.deviceResponse = response(200, DEVICE_LOGIN_JSON);

        try {
            auth.invokeGetRstsToken();
            fail("Expected cancellation");
        } catch (SafeguardForJavaException ex) {
            assertTrue(ex.getMessage().toLowerCase().contains("cancel"));
        }
        assertEquals(0, auth.requestTokenCalls);
    }

    @Test
    public void cancelHookAbortsDuringWaitPeriod() {
        DeviceCodeLoginParameters params = new DeviceCodeLoginParameters();
        params.setIsCancelled(() -> Boolean.TRUE);
        TestAuthenticator auth = newAuth(noopCallback(), params);

        // Production waitInterval must honor the cancel hook and not sleep at all.
        auth.waitInterval(10);
        assertEquals("Cancelled wait must not sleep", 0, auth.sleepCalls.get());
    }

    // ----- rSTS -> Safeguard UserToken exchange through AuthenticatorBase -----

    @Test
    public void refreshAccessTokenExchangesRstsTokenForUserToken() throws Exception {
        TestAuthenticator auth = newAuth(noopCallback(), defaultParams());
        auth.deviceResponse = response(200, DEVICE_LOGIN_JSON);
        auth.tokenResponses.add(response(200, "{\"access_token\":\"RSTS-EXCHANGE-ME\"}"));

        CapturingRestClient fakeCore = new CapturingRestClient("https://localhost/service/core/v4");
        fakeCore.responseToReturn = httpResponse(200, "{\"UserToken\":\"USER-TOKEN-42\"}");
        auth.coreClient = fakeCore;

        auth.refreshAccessToken();

        assertNotNull(auth.getAccessToken());
        assertEquals("USER-TOKEN-42", new String(auth.getAccessToken()));
        // Prove the authenticator only supplied the rSTS token to the base-class exchange.
        assertNotNull(fakeCore.lastPath);
        assertEquals("Token/LoginResponse", fakeCore.lastPath);
        assertTrue("Exchange body must carry the rSTS token: " + fakeCore.lastBody,
                fakeCore.lastBody.contains("RSTS-EXCHANGE-ME"));
    }

    // ----- Parameter validation and factory wiring -----

    @Test
    public void getIdIsDeviceCode() {
        TestAuthenticator auth = newAuth(noopCallback(), defaultParams());
        assertEquals("DeviceCode", auth.getId());
    }

    @Test
    public void parametersRejectNonPositivePollingInterval() {
        try {
            new DeviceCodeLoginParameters().setPollingIntervalSeconds(0);
            fail("Expected ArgumentException for non-positive interval");
        } catch (ArgumentException ex) {
            assertTrue(ex.getMessage().contains("greater than zero"));
        }
    }

    @Test
    public void parametersHaveExpectedDefaults() {
        DeviceCodeLoginParameters p = new DeviceCodeLoginParameters();
        assertEquals("rsts:sts:primaryproviderid:local", p.getScope());
        assertEquals("", p.getClientId());
        assertEquals(5, p.getPollingIntervalSeconds());
        assertEquals(Boolean.FALSE, p.getIsCancelled().get());
    }

    @Test
    public void constructorRejectsNullDisplayCallback() {
        try {
            new DeviceCodeAuthenticator("localhost", null, defaultParams(), 4, true, null);
            fail("Expected ArgumentException for null display callback");
        } catch (ArgumentException ex) {
            assertTrue(ex.getMessage().contains("displayCallback"));
        }
    }

    @Test
    public void connectDeviceCodeFactoryRejectsNullDisplayCallback() throws Exception {
        try {
            Safeguard.connectDeviceCode("localhost", null, null, (Integer) null, true);
            fail("Expected ArgumentException for null display callback");
        } catch (ArgumentException ex) {
            assertTrue(ex.getMessage().contains("displayCallback"));
        }
    }

    // ----- Test fixtures -----

    private static TestAuthenticator newAuth(IDeviceCodeDisplayCallback cb, DeviceCodeLoginParameters params) {
        try {
            return new TestAuthenticator("localhost", cb, params, 4, true, null);
        } catch (ArgumentException ex) {
            throw new RuntimeException(ex);
        }
    }

    private static DeviceCodeAuthenticator.RstsResponse response(int code, String body) {
        return new DeviceCodeAuthenticator.RstsResponse(code, body);
    }

    private static CloseableHttpResponse httpResponse(int code, String body) {
        BasicClassicHttpResponse r = new BasicClassicHttpResponse(code);
        r.setEntity(new StringEntity(body, ContentType.APPLICATION_JSON));
        return CloseableHttpResponse.adapt(r);
    }

    /**
     * Test double that scripts the rSTS responses and neutralizes the sleeper/clock.
     */
    private static final class TestAuthenticator extends DeviceCodeAuthenticator {

        RstsResponse deviceResponse;
        final Deque<RstsResponse> tokenResponses = new ArrayDeque<>();
        final Deque<Long> clockValues = new ArrayDeque<>();
        final AtomicInteger sleepCalls = new AtomicInteger(0);
        int requestTokenCalls;

        TestAuthenticator(String networkAddress, IDeviceCodeDisplayCallback displayCallback,
                DeviceCodeLoginParameters parameters, int apiVersion, boolean ignoreSsl,
                HostnameVerifier validationCallback) throws ArgumentException {
            super(networkAddress, displayCallback, parameters, apiVersion, ignoreSsl, validationCallback);
        }

        char[] invokeGetRstsToken() throws SafeguardForJavaException {
            try {
                return getRstsTokenInternal();
            } catch (com.oneidentity.safeguard.safeguardjava.exceptions.ObjectDisposedException ex) {
                throw new RuntimeException(ex);
            }
        }

        @Override
        protected RstsResponse requestDeviceCode(String clientId, String scope) {
            return deviceResponse;
        }

        @Override
        protected RstsResponse requestToken(String clientId, String deviceCode) {
            requestTokenCalls++;
            RstsResponse next = tokenResponses.poll();
            if (next == null) {
                throw new IllegalStateException("No scripted token response available");
            }
            return next;
        }

        @Override
        protected void sleepMillis(long millis) {
            sleepCalls.incrementAndGet();
        }

        @Override
        protected long monotonicMillis() {
            Long v = clockValues.poll();
            return v == null ? 0L : v;
        }
    }

    /**
     * Fake {@link RestClient} that records the posted exchange request and returns a
     * canned {@code Token/LoginResponse}.
     */
    private static final class CapturingRestClient extends RestClient {

        CloseableHttpResponse responseToReturn;
        String lastPath;
        String lastBody;

        CapturingRestClient(String baseUrl) {
            super(baseUrl, true, null);
        }

        @Override
        public CloseableHttpResponse execPOST(String path, Map<String, String> queryParams,
                Map<String, String> headers, Integer timeout, JsonObject requestEntity) {
            this.lastPath = path;
            try {
                this.lastBody = requestEntity == null ? null : requestEntity.toJson();
            } catch (SafeguardForJavaException ex) {
                throw new RuntimeException(ex);
            }
            return responseToReturn;
        }
    }
}

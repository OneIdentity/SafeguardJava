package com.oneidentity.safeguard.safeguardjava.authentication;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.oneidentity.safeguard.safeguardjava.AgentBasedLoginUtils;
import com.oneidentity.safeguard.safeguardjava.Utils;
import com.oneidentity.safeguard.safeguardjava.exceptions.ArgumentException;
import com.oneidentity.safeguard.safeguardjava.exceptions.ObjectDisposedException;
import com.oneidentity.safeguard.safeguardjava.exceptions.SafeguardForJavaException;
import com.oneidentity.safeguard.safeguardjava.restclient.RestClient;
import java.io.IOException;
import java.net.URLEncoder;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.cookie.BasicCookieStore;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.cookie.BasicClientCookie;
import org.apache.hc.client5.http.impl.io.BasicHttpClientConnectionManager;
import org.apache.hc.client5.http.socket.ConnectionSocketFactory;
import org.apache.hc.client5.http.ssl.NoopHostnameVerifier;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactory;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.HttpHeaders;
import org.apache.hc.core5.http.ParseException;
import org.apache.hc.core5.http.config.Registry;
import org.apache.hc.core5.http.config.RegistryBuilder;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.apache.hc.core5.http.io.entity.StringEntity;

/**
 * Authenticator that uses PKCE (Proof Key for Code Exchange) OAuth2 flow
 * to authenticate against Safeguard without requiring the password grant type.
 * <p>
 * This authenticator programmatically simulates the browser-based OAuth2/PKCE
 * flow by directly interacting with the rSTS login controller endpoints.
 */
public class PkceAuthenticator extends AuthenticatorBase {

    private static final Logger logger = LoggerFactory.getLogger(PkceAuthenticator.class);

    // rSTS login controller step numbers (from rSTS Login.js)
    private static final String STEP_INIT = "1";
    private static final String STEP_PRIMARY_AUTH = "3";
    private static final String STEP_SECONDARY_INIT = "7";
    private static final String STEP_SECONDARY_AUTH = "5";
    private static final String STEP_GENERATE_CLAIMS = "6";

    private boolean disposed;

    private final String provider;
    private String resolvedProviderId;
    private final String username;
    private final char[] password;
    private final char[] secondaryPassword;

    /**
     * Creates a PKCE authenticator for primary authentication only.
     *
     * @param networkAddress Network address of Safeguard appliance.
     * @param provider Safeguard authentication provider name (e.g. local).
     * @param username User name for authentication.
     * @param password User password for authentication.
     * @param apiVersion Target API version.
     * @param ignoreSsl Whether to ignore SSL certificate validation.
     * @param validationCallback Optional hostname verifier callback.
     * @throws ArgumentException If required arguments are null.
     */
    public PkceAuthenticator(String networkAddress, String provider, String username,
            char[] password, int apiVersion, boolean ignoreSsl,
            HostnameVerifier validationCallback) throws ArgumentException {
        this(networkAddress, provider, username, password, null, apiVersion, ignoreSsl, validationCallback);
    }

    /**
     * Creates a PKCE authenticator with support for multi-factor authentication.
     *
     * @param networkAddress Network address of Safeguard appliance.
     * @param provider Safeguard authentication provider name (e.g. local).
     * @param username User name for authentication.
     * @param password User password for authentication.
     * @param secondaryPassword One-time password for MFA (null if not required).
     * @param apiVersion Target API version.
     * @param ignoreSsl Whether to ignore SSL certificate validation.
     * @param validationCallback Optional hostname verifier callback.
     * @throws ArgumentException If required arguments are null.
     */
    public PkceAuthenticator(String networkAddress, String provider, String username,
            char[] password, char[] secondaryPassword, int apiVersion, boolean ignoreSsl,
            HostnameVerifier validationCallback) throws ArgumentException {
        super(networkAddress, apiVersion, ignoreSsl, validationCallback);
        this.provider = provider;
        this.username = username;
        if (password == null) {
            throw new ArgumentException("The password parameter can not be null");
        }
        this.password = password.clone();
        this.secondaryPassword = secondaryPassword != null ? secondaryPassword.clone() : null;
    }

    @Override
    public String getId() {
        return "PKCE";
    }

    @Override
    protected char[] getRstsTokenInternal() throws ObjectDisposedException, SafeguardForJavaException {
        if (disposed) {
            throw new ObjectDisposedException("PkceAuthenticator");
        }

        // Resolve the provider to an rSTS provider ID if needed
        if (resolvedProviderId == null) {
            resolvedProviderId = resolveIdentityProvider(provider);
        }

        String csrfToken = AgentBasedLoginUtils.generateCsrfToken();
        String codeVerifier = AgentBasedLoginUtils.oAuthCodeVerifier();
        String codeChallenge = AgentBasedLoginUtils.oAuthCodeChallenge(codeVerifier);
        String redirectUri = AgentBasedLoginUtils.REDIRECT_URI;

        CloseableHttpClient httpClient = createPkceHttpClient(getNetworkAddress(), csrfToken);

        try {
            String pkceUrl = String.format(
                    "https://%s/RSTS/UserLogin/LoginController?response_type=code&code_challenge_method=S256&code_challenge=%s&redirect_uri=%s&loginRequestStep=",
                    getNetworkAddress(), codeChallenge, redirectUri);

            String primaryFormData = String.format(
                    "directoryComboBox=%s&usernameTextbox=%s&passwordTextbox=%s&csrfTokenTextbox=%s",
                    URLEncoder.encode(resolvedProviderId, "UTF-8"),
                    URLEncoder.encode(username, "UTF-8"),
                    URLEncoder.encode(new String(password), "UTF-8"),
                    URLEncoder.encode(csrfToken, "UTF-8"));

            // Step 1: Initialize
            logger.debug("Calling RSTS for provider initialization");
            rstsFormPost(httpClient, pkceUrl + STEP_INIT, primaryFormData);

            // Step 3: Primary authentication
            logger.debug("Calling RSTS for primary authentication");
            String primaryBody = rstsFormPost(httpClient, pkceUrl + STEP_PRIMARY_AUTH, primaryFormData);

            // Handle secondary authentication (MFA) if required
            handleSecondaryAuthentication(httpClient, pkceUrl, primaryFormData, primaryBody);

            // Step 6: Generate claims
            logger.debug("Calling RSTS for generate claims");
            String claimsBody = rstsFormPost(httpClient, pkceUrl + STEP_GENERATE_CLAIMS, primaryFormData);

            // Extract authorization code from claims response
            String authorizationCode = extractAuthorizationCode(claimsBody);

            // Exchange authorization code for RSTS access token
            logger.debug("Redeeming RSTS authorization code");
            char[] rstsAccessToken = AgentBasedLoginUtils.postAuthorizationCodeFlow(
                    getNetworkAddress(), authorizationCode, codeVerifier, redirectUri,
                    isIgnoreSsl(), getValidationCallback());

            return rstsAccessToken;
        } catch (SafeguardForJavaException e) {
            throw e;
        } catch (Exception e) {
            throw new SafeguardForJavaException("PKCE authentication failed", e);
        } finally {
            try {
                httpClient.close();
            } catch (IOException e) {
                logger.warn("Failed to close PKCE HTTP client", e);
            }
        }
    }

    private void handleSecondaryAuthentication(CloseableHttpClient httpClient, String pkceUrl,
            String primaryFormData, String primaryAuthBody) throws SafeguardForJavaException {
        ObjectMapper mapper = new ObjectMapper();
        JsonNode primaryResponse;
        try {
            primaryResponse = mapper.readTree(primaryAuthBody);
        } catch (Exception e) {
            return; // Non-JSON response means no secondary auth info
        }

        if (primaryResponse == null) {
            return;
        }

        JsonNode secondaryProviderNode = primaryResponse.get("SecondaryProviderID");
        if (secondaryProviderNode == null || secondaryProviderNode.isNull()
                || Utils.isNullOrEmpty(secondaryProviderNode.asText())) {
            return; // No MFA required
        }

        String secondaryProviderId = secondaryProviderNode.asText();
        logger.debug("Secondary authentication required, provider: {}", secondaryProviderId);

        if (secondaryPassword == null) {
            throw new SafeguardForJavaException(
                    String.format("Multi-factor authentication is required (provider: %s) "
                            + "but no secondary password was provided.", secondaryProviderId));
        }

        try {
            // Step 7: Secondary provider initialization
            logger.debug("Calling RSTS for secondary provider initialization");
            String initBody = rstsFormPost(httpClient, pkceUrl + STEP_SECONDARY_INIT, primaryFormData);

            // Parse MFA state from secondary init response
            String mfaState = "";
            try {
                JsonNode initResponse = mapper.readTree(initBody);
                if (initResponse != null && initResponse.has("State")) {
                    mfaState = initResponse.get("State").asText("");
                }
            } catch (IOException e) {
                // Proceed without state
            }

            // Step 5: Submit secondary password (OTP)
            String mfaFormData = primaryFormData
                    + "&secondaryLoginTextbox=" + URLEncoder.encode(new String(secondaryPassword), "UTF-8")
                    + "&secondaryAuthenticationStateTextbox=" + URLEncoder.encode(mfaState, "UTF-8");

            logger.debug("Calling RSTS for secondary authentication");
            rstsFormPost(httpClient, pkceUrl + STEP_SECONDARY_AUTH, mfaFormData);

            logger.debug("Secondary authentication completed successfully");
        } catch (SafeguardForJavaException e) {
            throw e;
        } catch (IOException e) {
            throw new SafeguardForJavaException("Secondary authentication failed", e);
        }
    }

    private String extractAuthorizationCode(String response) throws SafeguardForJavaException {
        ObjectMapper mapper = new ObjectMapper();
        try {
            JsonNode jsonObject = mapper.readTree(response);
            JsonNode relyingPartyUrlNode = jsonObject.get("RelyingPartyUrl");

            if (relyingPartyUrlNode == null || relyingPartyUrlNode.isNull()
                    || Utils.isNullOrEmpty(relyingPartyUrlNode.asText())) {
                throw new SafeguardForJavaException(
                        "rSTS response did not contain a RelyingPartyUrl. "
                        + "The authentication process may be incomplete.");
            }

            String relyingPartyUrl = relyingPartyUrlNode.asText();

            // Parse the authorization code from the query string.
            // The URL may be a URN (e.g., urn:InstalledApplication?code=xxx)
            // or a standard HTTP URL, so we parse the query part manually.
            int queryStart = relyingPartyUrl.indexOf('?');
            if (queryStart >= 0) {
                String query = relyingPartyUrl.substring(queryStart + 1);
                for (String param : query.split("&")) {
                    String[] pair = param.split("=", 2);
                    if (pair.length == 2 && "code".equals(pair[0])) {
                        return java.net.URLDecoder.decode(pair[1], "UTF-8");
                    }
                }
            }

            throw new SafeguardForJavaException("rSTS response did not contain an authorization code");
        } catch (SafeguardForJavaException e) {
            throw e;
        } catch (Exception e) {
            throw new SafeguardForJavaException("Failed to parse authorization code from rSTS response", e);
        }
    }

    private String resolveIdentityProvider(String provider) throws SafeguardForJavaException {
        // If provider is null/empty or "local", use the local provider ID
        if (Utils.isNullOrEmpty(provider) || provider.equalsIgnoreCase("local")) {
            return "local";
        }

        // Use the existing resolveProviderToScope to find the matching provider,
        // but we need the RstsProviderId, not the scope. For PKCE we resolve it
        // by querying AuthenticationProviders and matching.
        try {
            String coreUrl = String.format("https://%s/service/core/v%d", getNetworkAddress(), getApiVersion());
            RestClient client = new RestClient(coreUrl, isIgnoreSsl(), getValidationCallback());

            java.util.Map<String, String> headers = new java.util.HashMap<>();
            headers.put(HttpHeaders.ACCEPT, "application/json");

            CloseableHttpResponse response = client.execGET("AuthenticationProviders", null, headers, null);

            if (response == null) {
                throw new SafeguardForJavaException("Unable to connect to Safeguard to resolve identity provider");
            }

            String reply = Utils.getResponse(response);
            if (!Utils.isSuccessful(response.getCode())) {
                throw new SafeguardForJavaException(
                        "Error requesting authentication providers, Error: "
                        + String.format("%d %s", response.getCode(), reply));
            }

            ObjectMapper mapper = new ObjectMapper();
            JsonNode providers = mapper.readTree(reply);

            if (providers != null && providers.isArray()) {
                for (JsonNode p : providers) {
                    String rstsProviderId = p.has("RstsProviderId") ? p.get("RstsProviderId").asText() : "";
                    String name = p.has("Name") ? p.get("Name").asText() : "";

                    if (rstsProviderId.equalsIgnoreCase(provider) || name.equalsIgnoreCase(provider)) {
                        return rstsProviderId;
                    }
                }
                // Broad match
                for (JsonNode p : providers) {
                    String rstsProviderId = p.has("RstsProviderId") ? p.get("RstsProviderId").asText() : "";
                    if (rstsProviderId.toLowerCase().contains(provider.toLowerCase())) {
                        return rstsProviderId;
                    }
                }
            }

            throw new SafeguardForJavaException(
                    String.format("Unable to find identity provider matching '%s'", provider));
        } catch (SafeguardForJavaException e) {
            throw e;
        } catch (Exception e) {
            throw new SafeguardForJavaException("Unable to resolve identity provider", e);
        }
    }

    /**
     * Posts form data to an rSTS login controller URL and returns the response body.
     */
    private String rstsFormPost(CloseableHttpClient httpClient, String url, String formData)
            throws SafeguardForJavaException {
        try {
            HttpPost post = new HttpPost(url);
            post.setHeader(HttpHeaders.ACCEPT, "application/json");
            post.setEntity(new StringEntity(formData, ContentType.APPLICATION_FORM_URLENCODED));

            CloseableHttpResponse response = httpClient.execute(post);
            String body = "";
            if (response.getEntity() != null) {
                body = EntityUtils.toString(response.getEntity());
            }

            int statusCode = response.getCode();
            // rSTS returns 203 for some secondary auth states — treat as non-error
            if (statusCode >= 400) {
                String errorMessage = !Utils.isNullOrEmpty(body) ? body.trim() : String.valueOf(statusCode);
                throw new SafeguardForJavaException(
                        String.format("rSTS authentication error: %s (HTTP %d)", errorMessage, statusCode));
            }

            return body;
        } catch (SafeguardForJavaException e) {
            throw e;
        } catch (ParseException | IOException e) {
            throw new SafeguardForJavaException("Failed to communicate with rSTS login controller", e);
        }
    }

    private CloseableHttpClient createPkceHttpClient(String appliance, String csrfToken) {
        try {
            SSLConnectionSocketFactory sslsf;
            if (isIgnoreSsl()) {
                SSLContext sslContext = SSLContext.getInstance("TLS");
                sslContext.init(null, new TrustManager[]{new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
                    public void checkClientTrusted(X509Certificate[] certs, String authType) { }
                    public void checkServerTrusted(X509Certificate[] certs, String authType) { }
                }}, new java.security.SecureRandom());
                sslsf = new SSLConnectionSocketFactory(sslContext, NoopHostnameVerifier.INSTANCE);
            } else if (getValidationCallback() != null) {
                SSLContext sslContext = SSLContext.getInstance("TLS");
                sslContext.init(null, new TrustManager[]{new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
                    public void checkClientTrusted(X509Certificate[] certs, String authType) { }
                    public void checkServerTrusted(X509Certificate[] certs, String authType) { }
                }}, new java.security.SecureRandom());
                sslsf = new SSLConnectionSocketFactory(sslContext, getValidationCallback());
            } else {
                sslsf = new SSLConnectionSocketFactory(SSLContext.getDefault());
            }

            Registry<ConnectionSocketFactory> socketFactoryRegistry = RegistryBuilder.<ConnectionSocketFactory>create()
                    .register("https", sslsf)
                    .build();
            BasicHttpClientConnectionManager connectionManager =
                    new BasicHttpClientConnectionManager(socketFactoryRegistry);

            // Set up cookie store with CSRF token
            BasicCookieStore cookieStore = new BasicCookieStore();
            BasicClientCookie csrfCookie = new BasicClientCookie("CsrfToken", csrfToken);
            csrfCookie.setDomain(appliance);
            csrfCookie.setPath("/RSTS");
            cookieStore.addCookie(csrfCookie);

            return HttpClients.custom()
                    .setConnectionManager(connectionManager)
                    .setDefaultCookieStore(cookieStore)
                    .build();
        } catch (Exception e) {
            throw new RuntimeException("Failed to create PKCE HTTP client", e);
        }
    }

    @Override
    public Object cloneObject() throws SafeguardForJavaException {
        try {
            PkceAuthenticator auth = new PkceAuthenticator(getNetworkAddress(), provider, username,
                    password, secondaryPassword, getApiVersion(), isIgnoreSsl(), getValidationCallback());
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
        if (password != null) {
            Arrays.fill(password, '0');
        }
        if (secondaryPassword != null) {
            Arrays.fill(secondaryPassword, '0');
        }
        disposed = true;
    }

    @Override
    protected void finalize() throws Throwable {
        try {
            if (password != null) {
                Arrays.fill(password, '0');
            }
            if (secondaryPassword != null) {
                Arrays.fill(secondaryPassword, '0');
            }
        } finally {
            disposed = true;
            super.finalize();
        }
    }
}

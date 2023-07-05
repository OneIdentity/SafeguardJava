package com.oneidentity.safeguard.safeguardjava.authentication;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.oneidentity.safeguard.safeguardjava.Utils;
import com.oneidentity.safeguard.safeguardjava.data.AccessTokenBody;
import com.oneidentity.safeguard.safeguardjava.exceptions.ObjectDisposedException;
import com.oneidentity.safeguard.safeguardjava.exceptions.SafeguardForJavaException;
import com.oneidentity.safeguard.safeguardjava.restclient.RestClient;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.HostnameVerifier;
import org.apache.http.HttpHeaders;
import org.apache.http.client.methods.CloseableHttpResponse;

abstract class AuthenticatorBase implements IAuthenticationMechanism {

    private boolean disposed;

    private final String networkAddress;
    private final int apiVersion;
    private final boolean ignoreSsl;
    private final HostnameVerifier validationCallback;

    protected char[] accessToken;

    protected final String safeguardRstsUrl;
    protected final String safeguardCoreUrl;

    protected RestClient rstsClient;
    protected RestClient coreClient;

    protected AuthenticatorBase(String networkAddress, int apiVersion, boolean ignoreSsl, HostnameVerifier validationCallback) {
        this.networkAddress = networkAddress;
        this.apiVersion = apiVersion;
        this.ignoreSsl = ignoreSsl;
        this.validationCallback = validationCallback;

        this.safeguardRstsUrl = String.format("https://%s/RSTS", this.networkAddress);
        this.rstsClient = new RestClient(safeguardRstsUrl, ignoreSsl, validationCallback);

        this.safeguardCoreUrl = String.format("https://%s/service/core/v%d", this.networkAddress, this.apiVersion);
        this.coreClient = new RestClient(safeguardCoreUrl, ignoreSsl, validationCallback);
    }

    public abstract String getId();

    @Override
    public String getNetworkAddress() {
        return networkAddress;
    }

    @Override
    public int getApiVersion() {
        return apiVersion;
    }

    @Override
    public boolean isIgnoreSsl() {
        return ignoreSsl;
    }

    @Override
    public HostnameVerifier getValidationCallback() {
        return validationCallback;
    }

    public boolean isAnonymous() {
        return false;
    }

    @Override
    public boolean hasAccessToken() {
        return accessToken != null;
    }

    @Override
    public void clearAccessToken() {
        if (accessToken != null) {
            Arrays.fill(accessToken, '0');
        }
        accessToken = null;
    }

    @Override
    public char[] getAccessToken() throws ObjectDisposedException {
        if (disposed) {
            throw new ObjectDisposedException("AuthenticatorBase");
        }
        return accessToken;
    }

    @Override
    public int getAccessTokenLifetimeRemaining() throws ObjectDisposedException, SafeguardForJavaException {
        if (disposed) {
            throw new ObjectDisposedException("AuthenticatorBase");
        }
        if (!hasAccessToken()) {
            return 0;
        }

        Map<String, String> headers = new HashMap<>();
        headers.put(HttpHeaders.AUTHORIZATION, String.format("Bearer %s", new String(accessToken)));
        headers.put("X-TokenLifetimeRemaining", "");

        CloseableHttpResponse response = coreClient.execGET("LoginMessage", null, headers, null);

        if (response == null) {
            throw new SafeguardForJavaException(String.format("Unable to connect to web service %s", coreClient.getBaseURL()));
        }
        if (!Utils.isSuccessful(response.getStatusLine().getStatusCode())) {
            return 0;
        }

        String remainingStr = null;
        if (response.containsHeader("X-TokenLifetimeRemaining")) {
            remainingStr = response.getFirstHeader("X-TokenLifetimeRemaining").getValue();
        }

        int remaining = 10; // Random magic value... the access token was good, but for some reason it didn't return the remaining lifetime
        if (remainingStr != null) {
            try {
                remaining = Integer.parseInt(remainingStr);
            } catch (Exception e) {
            }
        }

        return remaining;
    }

    @Override
    public void refreshAccessToken() throws ObjectDisposedException, SafeguardForJavaException {

        if (disposed) {
            throw new ObjectDisposedException("AuthenticatorBase");
        }

        char[] rStsToken = getRstsTokenInternal();
        AccessTokenBody body = new AccessTokenBody(rStsToken);
        CloseableHttpResponse response = coreClient.execPOST("Token/LoginResponse", null, null, null, body);

        if (response == null) {
            throw new SafeguardForJavaException(String.format("Unable to connect to web service %s", coreClient.getBaseURL()));
        }

        String reply = Utils.getResponse(response);
        if (!Utils.isSuccessful(response.getStatusLine().getStatusCode())) {
            throw new SafeguardForJavaException("Error exchanging RSTS token from " + this.getId() + "authenticator for Safeguard API access token, Error: "
                    + String.format("%d %s", response.getStatusLine().getStatusCode(), reply));
        }

        Map<String, String> map = Utils.parseResponse(reply);
        if (map.containsKey("UserToken")) {
            accessToken = map.get("UserToken").toCharArray();
        }
    }
    
    public String resolveProviderToScope(String provider) throws SafeguardForJavaException
    {
        try
        {
            CloseableHttpResponse response;
            Map<String,String> headers = new HashMap<>();
            
            headers.clear();
            headers.put(HttpHeaders.ACCEPT, "application/json");
        
            response = coreClient.execGET("AuthenticationProviders", null, headers, null);
                        
            if (response == null)
                throw new SafeguardForJavaException("Unable to connect to RSTS to find identity provider scopes");
            
            String reply = Utils.getResponse(response);
            if (!Utils.isSuccessful(response.getStatusLine().getStatusCode())) 
                throw new SafeguardForJavaException("Error requesting identity provider scopes from RSTS, Error: " +
                        String.format("%d %s", response.getStatusLine().getStatusCode(), reply));
            
            List<Provider> knownScopes = parseLoginResponse(reply);

            // 3 step check for determining if the user provided scope is valid:
            //
            // 1. User value == RSTSProviderId
            // 2. User value == Identity Provider Display Name.
            //    - This allows the caller to specify the domain name for AD.
            // 3. User Value is contained in RSTSProviderId.
            //    - This allows the caller to specify the provider Id rather than the full RSTSProviderId.
            //    - Such a broad check could provide some issues with false matching, however since this
            //      was in the original code, this check has been left in place.
            String scope = getMatchingScope(provider, knownScopes);

            if (scope == null)
            {
                StringBuilder s = new StringBuilder();
                knownScopes.forEach((p) -> {
                    if (s.length() > 0)
                        s.append(", ");
                    s.append(p.Name + ", " + p.RstsProviderId);
                });
                throw new SafeguardForJavaException(String.format("Unable to find scope matching '%s' in [%s]", provider, s.toString()));
            }
            
            return scope;
        }
        catch (SafeguardForJavaException ex) {
            throw ex;
        }
        catch (Exception ex)
        {
            throw new SafeguardForJavaException("Unable to connect to determine identity provider", ex);
        }
    }

    protected abstract char[] getRstsTokenInternal() throws ObjectDisposedException, SafeguardForJavaException;

    public abstract Object cloneObject() throws SafeguardForJavaException;

    @Override
    public void dispose() {
        clearAccessToken();
        disposed = true;
    }

    @Override
    protected void finalize() throws Throwable {
        try {

            if (accessToken != null) {
                Arrays.fill(accessToken, '0');
            }
        } finally {
            disposed = true;
            super.finalize();
        }
    }
    
    private class Provider {
        private String RstsProviderId;
        private String Name;
        private String RstsProviderScope;

        public Provider(String RstsProviderId, String Name, String RstsProviderScope) {
            this.RstsProviderId = RstsProviderId;
            this.Name = Name;
            this.RstsProviderScope = RstsProviderScope;
        }
    }
    
    private List<Provider> parseLoginResponse(String response) {
        
        List<Provider> providers = new ArrayList<>();
        ObjectMapper mapper = new ObjectMapper();
        
        try {
            JsonNode jsonNodeProviders = mapper.readTree(response);
            Iterator<JsonNode> iter = jsonNodeProviders.elements();
            
            while(iter.hasNext()){
		JsonNode providerNode=iter.next();
                Provider p = new Provider(getJsonValue(providerNode, "RstsProviderId"), getJsonValue(providerNode, "Name"), getJsonValue(providerNode, "RstsProviderScope"));
		providers.add(p);
            }            
        } catch (IOException ex) {
            Logger.getLogger(Utils.class.getName()).log(Level.SEVERE, null, ex);
        }

        return providers;
    }
    
    private String getMatchingScope(String provider, List<Provider> providers) {
        for (Provider s : providers) {
            if (s.Name.equalsIgnoreCase(provider) || s.RstsProviderId.equalsIgnoreCase(provider))
                return s.RstsProviderScope;
        }
        return null;
    }
    
    private String getJsonValue(JsonNode node, String propName) {
        if (node.get(propName) != null) {
            return node.get(propName).asText();
        }
        return null;
    }
}

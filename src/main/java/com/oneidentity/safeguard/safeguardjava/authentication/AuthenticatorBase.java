package com.oneidentity.safeguard.safeguardjava.authentication;

import com.oneidentity.safeguard.safeguardjava.Utils;
import com.oneidentity.safeguard.safeguardjava.data.AccessTokenBody;
import com.oneidentity.safeguard.safeguardjava.exceptions.ObjectDisposedException;
import com.oneidentity.safeguard.safeguardjava.exceptions.SafeguardForJavaException;
import com.oneidentity.safeguard.safeguardjava.restclient.RestClient;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import javax.ws.rs.core.Response;

abstract class AuthenticatorBase implements IAuthenticationMechanism
{
    private boolean disposed;

    private final String networkAddress; 
    private final int apiVersion;
    private boolean ignoreSsl;
    
    protected char[] accessToken;

    protected final String safeguardRstsUrl;
    protected final String safeguardCoreUrl;

    protected RestClient rstsClient;
    protected RestClient coreClient;

    protected AuthenticatorBase(String networkAddress, String certificatePath, char[] certificatePassword, int apiVersion, boolean ignoreSsl)
    {
        this.networkAddress = networkAddress;
        this.apiVersion = apiVersion;
        this.ignoreSsl = ignoreSsl;

        this.safeguardRstsUrl = String.format("https://%s/RSTS", this.networkAddress);
        this.rstsClient = new RestClient(safeguardRstsUrl, ignoreSsl);

        this.safeguardCoreUrl = String.format("https://%s/service/core/v%d", this.networkAddress, this.apiVersion);
        this.coreClient = new RestClient(safeguardCoreUrl, ignoreSsl);
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

    public boolean isAnonymous() {
        return false;
    }
    
    @Override
    public boolean hasAccessToken() {
        return accessToken != null;
    }

    public void clearAccessToken() {
        if (accessToken != null)
            Arrays.fill(accessToken, '0');
        accessToken = null;
    }
            
    @Override
    public char[] getAccessToken() throws ObjectDisposedException {
        if (disposed)
            throw new ObjectDisposedException("AuthenticatorBase");
        return accessToken;
    }

    @Override
    public int getAccessTokenLifetimeRemaining() throws ObjectDisposedException, SafeguardForJavaException {
        if (disposed)
            throw new ObjectDisposedException("AuthenticatorBase");
        if (!hasAccessToken())
            return 0;
        
        Map<String,String> headers = new HashMap<>();
        headers.put("Authorization", String.format("Bearer %s", new String(accessToken)));
        headers.put("X-TokenLifetimeRemaining", "");
        
        Response response = coreClient.execGET("LoginMessage", null, headers);
        
        if (response == null)
            throw new SafeguardForJavaException(String.format("Unable to connect to web service %s", coreClient.getBaseURL()));
        if (!Utils.isSuccessful(response.getStatus())) 
            return 0;

        String remainingStr = response.getHeaderString("X-TokenLifetimeRemaining");

        int remaining = 10; // Random magic value... the access token was good, but for some reason it didn't return the remaining lifetime
        if (remainingStr != null) {
            try {
                remaining = Integer.parseInt(remainingStr);
            }
            catch (Exception e) {
            }
        }
            
        return remaining;
    }

    @Override
    public void refreshAccessToken() throws ObjectDisposedException, SafeguardForJavaException {
        
        if (disposed)
            throw new ObjectDisposedException("AuthenticatorBase");
        
        char[] rStsToken = getRstsTokenInternal();
        AccessTokenBody body = new AccessTokenBody(rStsToken);
        Response response = coreClient.execPOST("Token/LoginResponse", null, null, body);

        if (response == null)
            throw new SafeguardForJavaException(String.format("Unable to connect to web service %s", coreClient.getBaseURL()));
        if (!Utils.isSuccessful(response.getStatus())) 
            throw new SafeguardForJavaException("Error exchanging RSTS token from " + this.getId() + "authenticator for Safeguard API access token, Error: " +
                                               String.format("%d %s", response.getStatus(), response.readEntity(String.class)));

        Map<String,String> map = Utils.parseResponse(response);
        if (map.containsKey("UserToken"))
            accessToken =  map.get("UserToken").toCharArray();
    }

    protected abstract char[] getRstsTokenInternal() throws ObjectDisposedException, SafeguardForJavaException;
    
    public abstract Object cloneObject() throws SafeguardForJavaException;
    
    @Override
    public void dispose()
    {
        clearAccessToken();
        disposed = true;
    }

    @Override
    protected void finalize() throws Throwable {
        try {
            
            if (accessToken != null)
                Arrays.fill(accessToken, '0');
        } finally {
            disposed = true;
            super.finalize();
        }
    }
    
}

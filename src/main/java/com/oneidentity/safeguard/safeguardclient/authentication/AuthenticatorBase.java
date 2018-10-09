package com.oneidentity.safeguard.safeguardclient.authentication;

import com.oneidentity.safeguard.safeguardclient.StringUtils;
import com.oneidentity.safeguard.safeguardclient.data.AccessTokenBody;
import com.oneidentity.safeguard.safeguardclient.exceptions.ObjectDisposedException;
import com.oneidentity.safeguard.safeguardclient.exceptions.SafeguardForJavaException;
import com.oneidentity.safeguard.safeguardclient.restclient.RestClient;
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
    public boolean hasAccessToken() {
        return accessToken != null;
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
        if (response.getStatus() != 200)
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
        if (response.getStatus() != 200)
            throw new SafeguardForJavaException("Error exchanging RSTS token for Safeguard API access token, Error: " +
                                               String.format("%d %s", response.getStatus(), response.readEntity(String.class)));

        Map<String,String> map = StringUtils.parseResponse(response);
        if (map.containsKey("UserToken"))
            accessToken =  map.get("UserToken").toCharArray();
    }

    protected abstract char[] getRstsTokenInternal() throws ObjectDisposedException, SafeguardForJavaException;
    
    @Override
    public void dispose()
    {
        Arrays.fill(accessToken, '0');
        disposed = true;
    }

    @Override
    protected void finalize() throws Throwable {
        try {
            Arrays.fill(accessToken, '0');
        } finally {
            disposed = true;
            super.finalize();
        }
    }
    
}

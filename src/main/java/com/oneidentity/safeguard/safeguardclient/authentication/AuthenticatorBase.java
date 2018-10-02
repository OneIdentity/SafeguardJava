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
    private boolean _disposed;

    private final String NetworkAddress; 
    private final int ApiVersion;
    private boolean IgnoreSsl;
    
    protected char[] AccessToken;

    protected final String SafeguardRstsUrl;
    protected final String SafeguardCoreUrl;

    protected RestClient RstsClient;
    protected RestClient CoreClient;

    protected AuthenticatorBase(String networkAddress, String certificatePath, char[] certificatePassword, int apiVersion, boolean ignoreSsl)
    {
        NetworkAddress = networkAddress;
        ApiVersion = apiVersion;

        SafeguardRstsUrl = String.format("https://%s/RSTS", NetworkAddress);
        RstsClient = new RestClient(SafeguardRstsUrl);

        SafeguardCoreUrl = String.format("https://%s/service/core/v%d", NetworkAddress, ApiVersion);
        CoreClient = new RestClient(SafeguardCoreUrl);

//        if (ignoreSsl)
//        {
//            IgnoreSsl = true;
//            RstsClient.RemoteCertificateValidationCallback += (sender, certificate, chain, errors) => true;
//            CoreClient.RemoteCertificateValidationCallback += (sender, certificate, chain, errors) => true;
//        }
    }

    public String getNetworkAddress() {
        return NetworkAddress;
    }

    public int getApiVersion() {
        return ApiVersion;
    }

    public boolean isIgnoreSsl() {
        return IgnoreSsl;
    }

    public boolean HasAccessToken() {
        return AccessToken != null;
    }

    public char[] GetAccessToken() throws ObjectDisposedException {
        if (_disposed)
            throw new ObjectDisposedException("AuthenticatorBase");
        return AccessToken;
    }

    public int GetAccessTokenLifetimeRemaining() throws ObjectDisposedException, SafeguardForJavaException {
        if (_disposed)
            throw new ObjectDisposedException("AuthenticatorBase");
        if (!HasAccessToken())
            return 0;
        
        Map<String,String> headers = new HashMap<>();
        headers.put("Authorization", String.format("Bearer %s", new String(AccessToken)));
        headers.put("X-TokenLifetimeRemaining", "");
        
        Response response = CoreClient.execGET("LoginMessage", null, headers);
        
//        if (response.getStatus() != 200)
//            throw new SafeguardForJavaException(String.format("Unable to connect to web service %s, Error: ", CoreClient.getBaseURL()) + response.readEntity(String.class));
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
    public void RefreshAccessToken() throws ObjectDisposedException, SafeguardForJavaException {
        
        if (_disposed)
            throw new ObjectDisposedException("AuthenticatorBase");
        
        char[] rStsToken = GetRstsTokenInternal();
        AccessTokenBody body = new AccessTokenBody(rStsToken);
        Response response = CoreClient.execPOST("Token/LoginResponse", null, null, body);

//        if (response.getStatus() != 200)
//            throw new SafeguardForJavaException(String.format("Unable to connect to web service %s, Error: ", CoreClient.getBaseURL()) + response.readEntity(String.class));
        if (response.getStatus() != 200)
            throw new SafeguardForJavaException("Error exchanging RSTS token for Safeguard API access token, Error: " +
                                               String.format("%d %s", response.getStatus(), response.readEntity(String.class)));

        Map<String,String> map = StringUtils.ParseResponse(response);
        AccessToken =  map.get("UserToken").toCharArray();
    }

    protected abstract char[] GetRstsTokenInternal() throws ObjectDisposedException, SafeguardForJavaException;
    
    public void Dispose()
    {
        Arrays.fill(AccessToken, '0');
        _disposed = true;
    }

    @Override
    protected void finalize() throws Throwable {
        try {
            Arrays.fill(AccessToken, '0');
        } finally {
            _disposed = true;
            super.finalize();
        }
    }
    
}

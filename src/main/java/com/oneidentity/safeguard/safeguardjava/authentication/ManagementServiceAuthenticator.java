package com.oneidentity.safeguard.safeguardjava.authentication;

import com.oneidentity.safeguard.safeguardjava.exceptions.ObjectDisposedException;
import com.oneidentity.safeguard.safeguardjava.exceptions.SafeguardForJavaException;
import javax.net.ssl.HostnameVerifier;

public class ManagementServiceAuthenticator implements IAuthenticationMechanism {

    private boolean disposed;
    
    private final String networkAddress;
    private final int apiVersion;
    private final boolean ignoreSsl;
    private final HostnameVerifier validationCallback;


    public ManagementServiceAuthenticator(IAuthenticationMechanism parentAuthenticationMechanism, String networkAddress) {
        this.apiVersion = parentAuthenticationMechanism.getApiVersion();
        this.ignoreSsl = parentAuthenticationMechanism.isIgnoreSsl();
        this.validationCallback = parentAuthenticationMechanism.getValidationCallback();
        this.networkAddress = networkAddress;
    }

    @Override
    public String getId() {
        return "Management";
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
    public HostnameVerifier getValidationCallback() {
        return validationCallback;
    }

    @Override
    public boolean isAnonymous() {
        return true;
    }
    
    @Override
    public boolean hasAccessToken() {
        return false;
    }
    
    @Override
    public void clearAccessToken() {
        // There is no access token for anonymous auth
    }

    @Override
    public char[] getAccessToken() throws ObjectDisposedException {
        return null;
    }

    @Override
    public int getAccessTokenLifetimeRemaining() throws ObjectDisposedException, SafeguardForJavaException {
        return 0;
    }
    
    @Override
    public void refreshAccessToken() throws ObjectDisposedException, SafeguardForJavaException {
        throw new SafeguardForJavaException("Anonymous connection cannot be used to get an API access token, Error: Unsupported operation");
    }
    
    @Override
    public String resolveProviderToScope(String provider) throws SafeguardForJavaException {
        throw new SafeguardForJavaException("Anonymous connection does not require a provider, Error: Unsupported operation");
    }
    
    @Override
    public Object cloneObject() throws SafeguardForJavaException {
        throw new SafeguardForJavaException("Anonymous authenticators are not cloneable");
    }
    
    @Override
    public void dispose() {
        disposed = true;
    }

    @Override
    protected void finalize() throws Throwable {
        try {
        } finally {
            disposed = true;
            super.finalize();
        }
    }
}

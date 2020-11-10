package com.oneidentity.safeguard.safeguardjava.authentication;

import com.oneidentity.safeguard.safeguardjava.exceptions.ObjectDisposedException;
import com.oneidentity.safeguard.safeguardjava.exceptions.SafeguardForJavaException;
import javax.net.ssl.HostnameVerifier;


public interface IAuthenticationMechanism
{
    String getId();
    String getNetworkAddress();
    int getApiVersion();
    boolean isIgnoreSsl();
    boolean isAnonymous();
    boolean hasAccessToken();
    void clearAccessToken();
    char[] getAccessToken() throws ObjectDisposedException;
    int getAccessTokenLifetimeRemaining() throws ObjectDisposedException, SafeguardForJavaException;
    HostnameVerifier getValidationCallback();
    void refreshAccessToken() throws ObjectDisposedException, SafeguardForJavaException;
    String resolveProviderToScope(String provider) throws SafeguardForJavaException;
    Object cloneObject() throws SafeguardForJavaException;
    void dispose();
}

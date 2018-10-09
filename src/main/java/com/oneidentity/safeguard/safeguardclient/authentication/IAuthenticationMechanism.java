package com.oneidentity.safeguard.safeguardclient.authentication;

import com.oneidentity.safeguard.safeguardclient.exceptions.ObjectDisposedException;
import com.oneidentity.safeguard.safeguardclient.exceptions.SafeguardForJavaException;


public interface IAuthenticationMechanism
{
    String getNetworkAddress();
    int getApiVersion();
    boolean isIgnoreSsl();
    boolean hasAccessToken();
    char[] getAccessToken() throws ObjectDisposedException;
    int getAccessTokenLifetimeRemaining() throws ObjectDisposedException, SafeguardForJavaException;
    void refreshAccessToken() throws ObjectDisposedException, SafeguardForJavaException;
    void dispose();
}

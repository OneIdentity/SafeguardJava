package com.oneidentity.safeguard.safeguardclient.authentication;

import com.oneidentity.safeguard.safeguardclient.exceptions.ObjectDisposedException;
import com.oneidentity.safeguard.safeguardclient.exceptions.SafeguardForJavaException;


public interface IAuthenticationMechanism
{
    String getNetworkAddress();
    int getApiVersion();
    boolean isIgnoreSsl();
    boolean HasAccessToken();
    char[] GetAccessToken() throws ObjectDisposedException;
    int GetAccessTokenLifetimeRemaining() throws ObjectDisposedException, SafeguardForJavaException;
    void RefreshAccessToken() throws ObjectDisposedException, SafeguardForJavaException;
    void Dispose();
}

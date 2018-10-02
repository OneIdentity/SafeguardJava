package com.oneidentity.safeguard.safeguardclient.authentication;

import com.oneidentity.safeguard.safeguardclient.exceptions.SafeguardForJavaException;

public class AccessTokenAuthenticator extends AuthenticatorBase
{
    private boolean _disposed;

    public AccessTokenAuthenticator(String networkAddress, char[] accessToken,
        int apiVersion, boolean ignoreSsl)
    {
        super(networkAddress, null, null, apiVersion, ignoreSsl);
        AccessToken = accessToken.clone();
    }

    @Override
    protected  char[] GetRstsTokenInternal() throws SafeguardForJavaException
    {
        throw new SafeguardForJavaException("Original authentication was with access token unable to refresh, Error: Unsupported operation");
    }

    @Override
    public void Dispose()
    {
        super.Dispose();
        _disposed = true;
    }
    
    @Override
    protected void finalize() throws Throwable {
        try {
        } finally {
            _disposed = true;
            super.finalize();
        }
    }
    
}

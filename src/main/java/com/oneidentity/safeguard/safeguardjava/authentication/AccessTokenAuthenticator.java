package com.oneidentity.safeguard.safeguardjava.authentication;

import com.oneidentity.safeguard.safeguardjava.exceptions.SafeguardForJavaException;

public class AccessTokenAuthenticator extends AuthenticatorBase
{
    private boolean disposed;

    public AccessTokenAuthenticator(String networkAddress, char[] accessToken,
        int apiVersion, boolean ignoreSsl)
    {
        super(networkAddress, null, null, apiVersion, ignoreSsl);
        this.accessToken = accessToken.clone();
    }

    @Override
    protected  char[] getRstsTokenInternal() throws SafeguardForJavaException
    {
        throw new SafeguardForJavaException("Original authentication was with access token unable to refresh, Error: Unsupported operation");
    }

    @Override
    public void dispose()
    {
        super.dispose();
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

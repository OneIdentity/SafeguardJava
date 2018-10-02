package com.oneidentity.safeguard.safeguardclient.authentication;

import com.oneidentity.safeguard.safeguardclient.exceptions.SafeguardForJavaException;

public class AnonymousAuthenticator extends AuthenticatorBase {

    private boolean _disposed;

    public AnonymousAuthenticator(String networkAddress, int apiVersion, boolean ignoreSsl) {
        super(networkAddress, null, null, apiVersion, ignoreSsl);
    }

    @Override
    protected char[] GetRstsTokenInternal() throws SafeguardForJavaException {
        throw new SafeguardForJavaException("Anonymous connection cannot be used to get an API access token, Error: Unsupported operation");
    }

    @Override
    public void Dispose() {
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

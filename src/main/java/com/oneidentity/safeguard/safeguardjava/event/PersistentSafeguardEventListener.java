package com.oneidentity.safeguard.safeguardjava.event;

import com.oneidentity.safeguard.safeguardjava.ISafeguardConnection;
import com.oneidentity.safeguard.safeguardjava.exceptions.ArgumentException;
import com.oneidentity.safeguard.safeguardjava.exceptions.ObjectDisposedException;
import com.oneidentity.safeguard.safeguardjava.exceptions.SafeguardForJavaException;
import java.util.logging.Level;
import java.util.logging.Logger;

public class PersistentSafeguardEventListener extends PersistentSafeguardEventListenerBase {

    private boolean disposed;

    private final ISafeguardConnection connection;

    public PersistentSafeguardEventListener(ISafeguardConnection connection) {
        this.connection = connection;
        Logger.getLogger(PersistentSafeguardEventListener.class.getName()).log(Level.INFO, "Persistent event listener successfully created.");
    }

    @Override
    public SafeguardEventListener reconnectEventListener()
            throws ObjectDisposedException, SafeguardForJavaException, ArgumentException {
        
        if (disposed) {
            throw new ObjectDisposedException("SafeguardEventListener");
        }
        
        if (connection.getAccessTokenLifetimeRemaining() == 0) {
            connection.refreshAccessToken();
        }
        return connection.getEventListener();
    }

    @Override
    public void dispose() {
        super.dispose();
        if (connection != null) {
            connection.dispose();
        }
        disposed = true;
    }

    @Override
    protected void finalize() throws Throwable {
        try {
            super.dispose();
            if (connection != null) {
                connection.dispose();
            }
        } finally {
            disposed = true;
            super.finalize();
        }
    }

}

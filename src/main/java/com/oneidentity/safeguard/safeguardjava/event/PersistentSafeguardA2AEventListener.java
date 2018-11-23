package com.oneidentity.safeguard.safeguardjava.event;

import com.oneidentity.safeguard.safeguardjava.ISafeguardA2AContext;
import com.oneidentity.safeguard.safeguardjava.exceptions.ArgumentException;
import com.oneidentity.safeguard.safeguardjava.exceptions.ObjectDisposedException;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;

class DefaultSafeguardEventHandler implements ISafeguardEventHandler {

    @Override
    public void onEventReceived(String eventName, String eventBody) {
    }
}

public class PersistentSafeguardA2AEventListener extends PersistentSafeguardEventListenerBase
{
    private boolean disposed;

    private final ISafeguardA2AContext a2AContext;
    private final char[] apiKey;

    public PersistentSafeguardA2AEventListener(ISafeguardA2AContext a2AContext, char[] apiKey, ISafeguardEventHandler handler) 
            throws ObjectDisposedException
    {
        this.a2AContext = a2AContext;
        this.apiKey = apiKey == null ? null : apiKey.clone();
        registerEventHandler("AssetAccountPasswordUpdated", handler);
        Logger.getLogger(PersistentSafeguardA2AEventListener.class.getName()).log(Level.INFO, "Persistent A2A event listener successfully created.");
}

    @Override
    public SafeguardEventListener reconnectEventListener() throws ObjectDisposedException, ArgumentException
    {
        // passing in a bogus handler because it will be overridden in PersistentSafeguardEventListenerBase
        return (SafeguardEventListener) a2AContext.getEventListener(apiKey, new DefaultSafeguardEventHandler());
    }

    @Override
    public void dispose()
    {
        super.dispose();
        if (apiKey != null)
            Arrays.fill(apiKey, '0');
        if (a2AContext != null)
            a2AContext.dispose();
        disposed = true;
    }
    
    @Override
    protected void finalize() throws Throwable {
        try {
            if (apiKey != null)
                Arrays.fill(apiKey, '0');
            if (a2AContext != null)
                a2AContext.dispose();
        } finally {
            disposed = true;
            super.finalize();
        }
    }
    
}

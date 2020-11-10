package com.oneidentity.safeguard.safeguardjava.event;

import com.oneidentity.safeguard.safeguardjava.ISafeguardA2AContext;
import com.oneidentity.safeguard.safeguardjava.exceptions.ArgumentException;
import com.oneidentity.safeguard.safeguardjava.exceptions.ObjectDisposedException;
import com.oneidentity.safeguard.safeguardjava.exceptions.SafeguardForJavaException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
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
    private final List<char[]> apiKeys;

    public PersistentSafeguardA2AEventListener(ISafeguardA2AContext a2AContext, char[] apiKey, ISafeguardEventHandler handler)
            throws ObjectDisposedException, ArgumentException {
        this.a2AContext = a2AContext;
        if (apiKey == null) {
            throw new ArgumentException("The apiKey parameter can not be null");
        }
        this.apiKey = apiKey.clone();
        this.apiKeys = null;
        registerEventHandler("AssetAccountPasswordUpdated", handler);
        registerEventHandler("AssetAccountSshKeyUpdated", handler);
        Logger.getLogger(PersistentSafeguardA2AEventListener.class.getName()).log(Level.FINEST, "Persistent A2A event listener successfully created.");
    }

    public PersistentSafeguardA2AEventListener(ISafeguardA2AContext a2AContext, List<char[]> apiKeys, ISafeguardEventHandler handler) 
            throws ArgumentException, ObjectDisposedException {
        this.a2AContext = a2AContext;
        if (apiKeys == null) {
            throw new ArgumentException("The apiKey parameter can not be null");
        }
        this.apiKey = null;
        this.apiKeys = new ArrayList<char[]>();
        for (char[] apiKey : apiKeys) {
            this.apiKeys.add(apiKey.clone());
        }
        if (this.apiKeys.isEmpty()) {
            throw new ArgumentException("Parameter apiKeys must include at least one item");
        }
        registerEventHandler("AssetAccountPasswordUpdated", handler);
        registerEventHandler("AssetAccountSshKeyUpdated", handler);
        Logger.getLogger(PersistentSafeguardA2AEventListener.class.getName()).log(Level.FINEST, "Persistent A2A event listener successfully created.");
    }
    
    @Override
    public SafeguardEventListener reconnectEventListener() throws ObjectDisposedException, ArgumentException
    {
        // passing in a bogus handler because it will be overridden in PersistentSafeguardEventListenerBase
        if (this.apiKey != null)
            return (SafeguardEventListener) a2AContext.getA2AEventListener(this.apiKey, new DefaultSafeguardEventHandler());
        return (SafeguardEventListener) a2AContext.getA2AEventListener(this.apiKeys, new DefaultSafeguardEventHandler());
    }

    @Override
    public void dispose()
    {
        super.dispose();
        if (apiKey != null)
            Arrays.fill(apiKey, '0');
        if (apiKeys != null)
            for (char[] apiKey : apiKeys)
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
            if (apiKeys != null)
                for (char[] apiKey : apiKeys)
                    Arrays.fill(apiKey, '0');
            if (a2AContext != null)
                a2AContext.dispose();
        } finally {
            disposed = true;
            super.finalize();
        }
    }
    
}

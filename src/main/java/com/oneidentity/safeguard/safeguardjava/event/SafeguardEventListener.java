package com.oneidentity.safeguard.safeguardjava.event;

import com.google.gson.JsonElement;
import com.oneidentity.safeguard.safeguardjava.data.CertificateContext;
import com.oneidentity.safeguard.safeguardjava.exceptions.ArgumentException;
import com.oneidentity.safeguard.safeguardjava.exceptions.ObjectDisposedException;
import com.oneidentity.safeguard.safeguardjava.exceptions.SafeguardEventListenerDisconnectedException;
import com.oneidentity.safeguard.safeguardjava.exceptions.SafeguardForJavaException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.HostnameVerifier;
import microsoft.aspnet.signalr.client.ErrorCallback;
import microsoft.aspnet.signalr.client.MessageReceivedHandler;
import microsoft.aspnet.signalr.client.SignalRFuture;
import microsoft.aspnet.signalr.client.hubs.HubConnection;
import microsoft.aspnet.signalr.client.hubs.HubProxy;

class DefaultDisconnectHandler implements IDisconnectHandler {

    @Override
    public void func() throws SafeguardEventListenerDisconnectedException {
        throw new SafeguardEventListenerDisconnectedException();
    }
}

public class SafeguardEventListener implements ISafeguardEventListener {

    private boolean disposed;

    private final String eventUrl;
    private final boolean ignoreSsl;
    private final HostnameVerifier validationCallback;
    private char[] accessToken;
    private char[] apiKey;
    private List<char[]> apiKeys;
    private CertificateContext clientCertificate;

    private EventHandlerRegistry eventHandlerRegistry;
    private IDisconnectHandler disconnectHandler;

    private HubConnection signalrConnection = null;
    private SignalRFuture<Void> signalrFuture = null;
    public HubProxy signalrHubProxy = null;

    private static final String NOTIFICATION_HUB = "notificationHub";

    private SafeguardEventListener(String eventUrl, boolean ignoreSsl, HostnameVerifier validationCallback) {
        this.eventUrl = eventUrl;
        this.ignoreSsl = ignoreSsl;
        this.validationCallback = validationCallback;
        this.eventHandlerRegistry = new EventHandlerRegistry();
        this.accessToken = null;
        this.apiKey = null;
        this.apiKeys = null;
        this.clientCertificate = null;
        this.disconnectHandler = new DefaultDisconnectHandler();
    }

    public SafeguardEventListener(String eventUrl, char[] accessToken, boolean ignoreSsl, HostnameVerifier validationCallback) throws ArgumentException {
        this(eventUrl, ignoreSsl, validationCallback);
        if (accessToken == null)
            throw new ArgumentException("The accessToken parameter can not be null");
        this.accessToken = accessToken.clone();
    }

    public SafeguardEventListener(String eventUrl, String clientCertificatePath, char[] certificatePassword, 
            String certificateAlias, char[] apiKey, boolean ignoreSsl, HostnameVerifier validationCallback) throws ArgumentException {
        this(eventUrl, ignoreSsl, validationCallback);
        if (apiKey == null)
            throw new ArgumentException("The apiKey parameter can not be null");
        this.apiKey = apiKey.clone();
        this.clientCertificate = new CertificateContext(certificateAlias, clientCertificatePath, null, certificatePassword);
    }
    
    public SafeguardEventListener(String eventUrl, CertificateContext clientCertificate, 
            char[] apiKey, boolean ignoreSsl, HostnameVerifier validationCallback) throws ArgumentException {
        this(eventUrl, ignoreSsl, validationCallback);
        if (apiKey == null)
            throw new ArgumentException("The apiKey parameter can not be null");
        this.clientCertificate = clientCertificate.cloneObject();
        this.apiKey = apiKey.clone();
    }
    
    public SafeguardEventListener(String eventUrl, String clientCertificatePath, char[] certificatePassword, 
            String certificateAlias, List<char[]> apiKeys, boolean ignoreSsl, HostnameVerifier validationCallback) throws ArgumentException {
        this(eventUrl, ignoreSsl, validationCallback);
        if (apiKeys == null)
            throw new ArgumentException("The apiKey parameter can not be null");
        
        this.clientCertificate = new CertificateContext(certificateAlias, clientCertificatePath, null, certificatePassword);
        this.apiKeys = new ArrayList<>();
        for (char[] key : apiKeys)
            apiKeys.add(key.clone());
        if (apiKeys.isEmpty())
            throw new ArgumentException("The apiKeys parameter must include at least one item");
    }
    
    public SafeguardEventListener(String eventUrl, CertificateContext clientCertificate, 
            List<char[]> apiKeys, boolean ignoreSsl, HostnameVerifier validationCallback) throws ArgumentException
    {
        this(eventUrl, ignoreSsl, validationCallback);
        if (apiKeys == null)
            throw new ArgumentException("The apiKeys parameter can not be null");
        
        this.clientCertificate = clientCertificate.cloneObject();
        this.apiKeys = new ArrayList<>();
        for (char[] key : apiKeys)
            apiKeys.add(key.clone());
        if (apiKeys.isEmpty())
            throw new ArgumentException("The apiKeys parameter must include at least one item");
    }

    public void setDisconnectHandler(IDisconnectHandler handler) {
        this.disconnectHandler = handler;
    }

    public void setEventHandlerRegistry(EventHandlerRegistry registry) {
        this.eventHandlerRegistry = registry;
    }

    private void handleEvent(JsonElement eventObject) {
        eventHandlerRegistry.handleEvent(eventObject);
    }

    private void handleDisconnect() throws SafeguardEventListenerDisconnectedException {
        if (!this.isStarted()) {
            return;
        }
        Logger.getLogger(EventHandlerRegistry.class.getName()).log(Level.WARNING, "SignalR disconnect detected, calling handler...");
        disconnectHandler.func();
    }
    
    private void cleanupConnection() {
        try {
        } finally {
            signalrConnection = null;
            signalrHubProxy = null;
            signalrFuture = null;
        }
    }

    @Override
    public boolean isStarted() {
        return signalrFuture == null ? false : signalrFuture.isDone();
    }
    
    @Override
    public void registerEventHandler(String eventName, ISafeguardEventHandler handler)
            throws ObjectDisposedException {
        if (disposed) {
            throw new ObjectDisposedException("SafeguardEventListener");
        }
        eventHandlerRegistry.registerEventHandler(eventName, handler);
    }

    @Override
    public void start() throws ObjectDisposedException, SafeguardForJavaException, SafeguardEventListenerDisconnectedException {
        if (disposed) {
            throw new ObjectDisposedException("SafeguardEventListener");
        }
        cleanupConnection();

        signalrConnection = new HubConnection(eventUrl);
        if (accessToken != null) {
            signalrConnection.getHeaders().put("Authorization", String.format("Bearer %s", new String(accessToken)));
        } else {
            String authKey = "";
            if (apiKey != null)
                authKey = new String(apiKey);
            else if (apiKeys != null) {
                for (char[] key : apiKeys)
                    authKey += new String(key) + " ";
                authKey = authKey.trim();
            }

            if (authKey.isEmpty())
                throw new SafeguardForJavaException("No API keys found in the authorization header");

            signalrConnection.getHeaders().put("Authorization", String.format("A2A %s", authKey));
            signalrConnection.setClientCertificate(clientCertificate.getCertificatePath(), clientCertificate.getCertificatePassword(), clientCertificate.getCertificateAlias());
        }
        signalrHubProxy = signalrConnection.createHubProxy(NOTIFICATION_HUB);

        try {
            // The java version of Signalr doesn't support a HostnameVerifier callback.  So if
            //  one is set then it will be the same as ignoreSsl.
            signalrFuture = signalrConnection.start(ignoreSsl || (this.validationCallback != null));
            
            signalrConnection.received(new MessageReceivedHandler() {
                @Override
                public void onMessageReceived(JsonElement json) {
                    handleEvent(json);
                }
            });
            signalrConnection.closed(new Runnable() {
                @Override
                public void run() {
                    try {
                        handleDisconnect();
                    } catch (SafeguardEventListenerDisconnectedException ex) {
                        Logger.getLogger(SafeguardEventListener.class.getName()).log(Level.SEVERE, null, ex);
                    }
                }
            });
            signalrConnection.error(new ErrorCallback() {
                @Override
                public void onError(Throwable error) {
                    Logger.getLogger(EventHandlerRegistry.class.getName()).log(Level.WARNING, "SignalR error detected...", error.getMessage());
                }
            });
            
        } catch (Exception ex) {
            throw new SafeguardForJavaException("Failure starting SignalR", ex);
        }
    }

    @Override
    public void stop() throws ObjectDisposedException, SafeguardForJavaException {
        if (disposed) {
            throw new ObjectDisposedException("SafeguardEventListener");
        }
        try {
            if (signalrConnection != null) {
                signalrConnection.stop();
            }
            cleanupConnection();
        } catch (Exception ex) {
            throw new SafeguardForJavaException("Failure stopping SignalR.", ex);
        }
    }

    @Override
    public void dispose() {
        cleanupConnection();
        if (clientCertificate != null)
            clientCertificate.dispose();
        if (apiKey != null)
            Arrays.fill(apiKey, '0');
        if (apiKeys != null)
            for (char[] key : apiKeys)
                Arrays.fill(key, '0');
        if (accessToken != null)
            Arrays.fill(accessToken, '0');
        disposed = true;
    }

    @Override
    protected void finalize() throws Throwable {
        try {
            cleanupConnection();
            if (clientCertificate != null)
                clientCertificate.dispose();
            if (apiKey != null)
                Arrays.fill(apiKey, '0');
            if (apiKeys != null)
                for (char[] key : apiKeys)
                    Arrays.fill(key, '0');
            if (accessToken != null)
                Arrays.fill(accessToken, '0');
            disposed = true;
        } finally {
            disposed = true;
            super.finalize();
        }
    }
}

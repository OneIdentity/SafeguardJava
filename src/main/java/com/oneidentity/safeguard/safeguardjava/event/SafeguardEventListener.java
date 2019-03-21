package com.oneidentity.safeguard.safeguardjava.event;

import com.google.gson.JsonElement;
import com.oneidentity.safeguard.safeguardjava.exceptions.ArgumentException;
import com.oneidentity.safeguard.safeguardjava.exceptions.ObjectDisposedException;
import com.oneidentity.safeguard.safeguardjava.exceptions.SafeguardEventListenerDisconnectedException;
import com.oneidentity.safeguard.safeguardjava.exceptions.SafeguardForJavaException;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;
import microsoft.aspnet.signalr.client.ErrorCallback;
import microsoft.aspnet.signalr.client.MessageReceivedHandler;
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
    private char[] accessToken;
    private char[] apiKey;
    private String clientCertificatePath;
    private char[] clientCertificatePassword;
    private String clientCertificateAlias;

    private EventHandlerRegistry eventHandlerRegistry;
    private IDisconnectHandler disconnectHandler;

    private boolean isStarted;
    private HubConnection signalrConnection = null;
    public HubProxy signalrHubProxy = null;

    private static final String NOTIFICATION_HUB = "notificationHub";

    private SafeguardEventListener(String eventUrl, boolean ignoreSsl) {
        this.eventUrl = eventUrl;
        this.ignoreSsl = ignoreSsl;
        this.eventHandlerRegistry = new EventHandlerRegistry();
        this.accessToken = null;
        this.apiKey = null;
        this.clientCertificatePath = null;
        this.clientCertificatePassword = null;
        this.clientCertificateAlias = null;
        this.disconnectHandler = new DefaultDisconnectHandler();
    }

    public SafeguardEventListener(String eventUrl, char[] accessToken, boolean ignoreSsl) throws ArgumentException {
        this(eventUrl, ignoreSsl);
        if (accessToken == null)
            throw new ArgumentException("The accessToken parameter can not be null");
        this.accessToken = accessToken.clone();
    }

    public SafeguardEventListener(String eventUrl, String clientCertificatePath, char[] certificatePassword, 
            String certificateAlias, char[] apiKey, boolean ignoreSsl) throws ArgumentException {
        this(eventUrl, ignoreSsl);
        this.clientCertificatePath = clientCertificatePath;
        this.clientCertificatePassword = certificatePassword == null ? null : certificatePassword.clone();
        this.clientCertificateAlias = certificateAlias;
        if (apiKey == null)
            throw new ArgumentException("The apiKey parameter can not be null");
        this.apiKey = apiKey.clone();
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
        if (!this.isStarted) {
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
            isStarted = false;
        }
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
            signalrConnection.getHeaders().put("Authorization", String.format("A2A %s", new String(apiKey)));
            signalrConnection.setClientCertificate(clientCertificatePath, clientCertificatePassword, clientCertificateAlias);
        }
        signalrHubProxy = signalrConnection.createHubProxy(NOTIFICATION_HUB);

        try {
//            ClientTransport clientTransport = 
//                    new ServerSentEventsTransport(new NullLogger(), Platform.createDefaultHttpsConnection(new NullLogger(), ignoreSsl));
//            signalrConnection.start(clientTransport).get();
            signalrConnection.start(ignoreSsl).get();
            
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
            
            this.isStarted = true;

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
            isStarted = false;
            if (signalrConnection != null) {
                signalrConnection.stop();
            }
            cleanupConnection();
        } catch (Exception ex) {
            throw new SafeguardForJavaException("Failure stopping SignalR", ex);
        }
    }

    @Override
    public void dispose() {
        cleanupConnection();
        clientCertificatePath = null;
        clientCertificateAlias = null;
        if (apiKey != null)
            Arrays.fill(apiKey, '0');
        if (accessToken != null)
            Arrays.fill(accessToken, '0');
        if (clientCertificatePassword != null)
            Arrays.fill(clientCertificatePassword, '0');
        disposed = true;
    }

    @Override
    protected void finalize() throws Throwable {
        try {
            cleanupConnection();
            clientCertificatePath = null;
            clientCertificateAlias = null;
            if (apiKey != null)
                Arrays.fill(apiKey, '0');
            if (accessToken != null)
                Arrays.fill(accessToken, '0');
            if (clientCertificatePassword != null)
                Arrays.fill(clientCertificatePassword, '0');
            disposed = true;
        } finally {
            disposed = true;
            super.finalize();
        }
    }
}

package com.oneidentity.safeguard.safeguardjava.event;

import com.google.gson.JsonElement;
import com.oneidentity.safeguard.safeguardjava.exceptions.ObjectDisposedException;
import com.oneidentity.safeguard.safeguardjava.exceptions.SafeguardEventListenerDisconnectedException;
import com.oneidentity.safeguard.safeguardjava.exceptions.SafeguardForJavaException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;
import microsoft.aspnet.signalr.client.ErrorCallback;
import microsoft.aspnet.signalr.client.MessageReceivedHandler;
import microsoft.aspnet.signalr.client.NullLogger;
import microsoft.aspnet.signalr.client.Platform;
import microsoft.aspnet.signalr.client.hubs.HubConnection;
import microsoft.aspnet.signalr.client.hubs.HubProxy;
import microsoft.aspnet.signalr.client.transport.ClientTransport;
import microsoft.aspnet.signalr.client.transport.ServerSentEventsTransport;

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
    private X509Certificate clientCertificate;

    private EventHandlerRegistry eventHandlerRegistry;
    private IDisconnectHandler disconnectHandler;

    private boolean isStarted;
    private HubConnection signalrConnection = null;
//    private Subscription handlerSubscription = null;
    public HubProxy signalrHubProxy = null;

    private static final String NOTIFICATION_HUB = "notificationHub";

    private SafeguardEventListener(String eventUrl, boolean ignoreSsl) {
        this.eventUrl = eventUrl;
        this.ignoreSsl = ignoreSsl;
        this.eventHandlerRegistry = new EventHandlerRegistry();
        this.accessToken = null;
        this.apiKey = null;
        this.clientCertificate = null;
        this.disconnectHandler = new DefaultDisconnectHandler();
    }

    public SafeguardEventListener(String eventUrl, char[] accessToken, boolean ignoreSsl) {
        this(eventUrl, ignoreSsl);
        this.accessToken = accessToken.clone();
    }

    public SafeguardEventListener(String eventUrl, X509Certificate clientCertificate, char[] apiKey, boolean ignoreSsl) {
        this(eventUrl, ignoreSsl);
//        clientCertificate = CertificateUtilities.Copy(clientCertificate);
        this.apiKey = apiKey.clone();
    }

    public void setDisconnectHandler(IDisconnectHandler handler) {
        this.disconnectHandler = handler;
    }

    public void setEventHandlerRegistry(EventHandlerRegistry registry) {
        this.eventHandlerRegistry = registry;
    }

    private void handleEvent(JsonElement eventObject) {
//Do nothing for now
        int x = 1;
//        eventHandlerRegistry.handleEvent(eventObject);
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
//            if (handlerSubscription != null) {
//                handlerSubscription.unsubscribe();
//            }
//            if (signalrConnection != null) {
//                signalrConnection.remove(eventUrl);
//            }
        } finally {
            signalrConnection = null;
//            handlerSubscription = null;
            signalrHubProxy = null;
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
//            this.signalrConnection.addClientCertificate(clientCertificate);
        }
        signalrHubProxy = signalrConnection.createHubProxy(NOTIFICATION_HUB);

        try {
//            ClientTransport clientTransport = new ServerSentEventsTransport(new NullLogger(), Platform.createHttpConnection(new NullLogger()));
//            signalrConnection.start(clientTransport).get();
            signalrConnection.start().get();
            
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
        if (this.accessToken != null) {
            Arrays.fill(this.accessToken, '0');
        }
//        if (this.clientCertificate != null)
//            this.clientCertificate = null;
        if (this.apiKey != null) {
            Arrays.fill(this.apiKey, '0');
        }
        disposed = true;
    }

    @Override
    protected void finalize() throws Throwable {
        try {
            cleanupConnection();
            if (this.accessToken != null) {
                Arrays.fill(this.accessToken, '0');
            }
//            if (this.clientCertificate != null)
//                this.clientCertificate = null;
            if (this.apiKey != null) {
                Arrays.fill(this.apiKey, '0');
            }
        } finally {
            disposed = true;
        }
    }
}

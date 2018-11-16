package com.oneidentity.safeguard.safeguardjava.event;

import com.microsoft.signalr.HttpHubConnectionBuilder;
import com.microsoft.signalr.HubConnection;
import com.microsoft.signalr.HubConnectionBuilder;
import com.microsoft.signalr.HubConnectionState;
import com.microsoft.signalr.Subscription;
import com.oneidentity.safeguard.safeguardjava.exceptions.ObjectDisposedException;
import com.oneidentity.safeguard.safeguardjava.exceptions.SafeguardEventListenerDisconnectedException;
import com.oneidentity.safeguard.safeguardjava.exceptions.SafeguardForJavaException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;

class DefaultDisconnectHandler implements IDisconnectHandler {

    @Override
    public void func() throws SafeguardEventListenerDisconnectedException {
        throw new SafeguardEventListenerDisconnectedException();
    }
}

public class SafeguardEventListener implements ISafeguardEventListener
{
    private boolean disposed;

    private final String eventUrl;
    private final boolean ignoreSsl;
    private char[] accessToken;
    private char[] apiKey;
    private X509Certificate clientCertificate;

    private EventHandlerRegistry eventHandlerRegistry;
//    private IDisconnectHandler _disconnectHandler = () => throw new SafeguardEventListenerDisconnectedException();
    private IDisconnectHandler disconnectHandler;

    private boolean isStarted;
    private HubConnection signalrConnection = null;
    private Subscription handlerSubscription = null;

    private static final String NOTIFICATION_HUB = "notificationHub";

    private SafeguardEventListener(String eventUrl, boolean ignoreSsl)
    {
        this.eventUrl = eventUrl;
        this.ignoreSsl = ignoreSsl;
        this.eventHandlerRegistry = new EventHandlerRegistry();
        this.accessToken = null;
        this.apiKey = null;
        this.clientCertificate = null;
        this.disconnectHandler = new DefaultDisconnectHandler();
    }

    public SafeguardEventListener(String eventUrl, char[] accessToken, boolean ignoreSsl) 
    {
        this(eventUrl, ignoreSsl);
        this.accessToken = accessToken.clone();
    }

    public SafeguardEventListener(String eventUrl, X509Certificate clientCertificate, char[] apiKey, boolean ignoreSsl)
    {
        this(eventUrl, ignoreSsl);
//        clientCertificate = CertificateUtilities.Copy(clientCertificate);
        this.apiKey = apiKey.clone();
    }

    public void setDisconnectHandler(IDisconnectHandler handler)
    {
        this.disconnectHandler = handler;
    }

    public void setEventHandlerRegistry(EventHandlerRegistry registry)
    {
        this.eventHandlerRegistry = registry;
    }

    private void handleEvent(String eventObject)
    {
        eventHandlerRegistry.handleEvent(eventObject);
    }

    private void handleDisconnect(Exception consumer) throws SafeguardEventListenerDisconnectedException {
        if (!this.isStarted)
            return;
        Logger.getLogger(EventHandlerRegistry.class.getName()).log(Level.WARNING, "SignalR disconnect detected, calling handler...", consumer);
        disconnectHandler.func();
    }

    private void cleanupConnection()
    {
        try
        {
            if (handlerSubscription != null) {
                handlerSubscription.unsubscribe();
            }
            if (signalrConnection != null) {
                signalrConnection.remove(eventUrl);
            }
        }
        finally
        {
            signalrConnection = null;
            handlerSubscription = null;
        }
    }

    @Override
    public void registerEventHandler(String eventName, ISafeguardEventHandler handler) 
            throws ObjectDisposedException
    {
        if (disposed)
            throw new ObjectDisposedException("SafeguardEventListener");
        eventHandlerRegistry.registerEventHandler(eventName, handler);
    }

    @Override
    public void start() throws ObjectDisposedException, SafeguardForJavaException, SafeguardEventListenerDisconnectedException
    {
        if (disposed)
            throw new ObjectDisposedException("SafeguardEventListener");
        cleanupConnection();
        
        HttpHubConnectionBuilder signalrConnectionBuilder = HubConnectionBuilder.create(eventUrl);
        if (accessToken != null) {
            signalrConnectionBuilder = signalrConnectionBuilder.withHeader("Authorization", String.format("Bearer %s", new String(accessToken)));
        }
        else
        {
            signalrConnectionBuilder = signalrConnectionBuilder.withHeader("Authorization", String.format("A2A %s", new String(apiKey)));
//            this.signalrConnection.addClientCertificate(clientCertificate);
        }
//        signalrConnectionBuilder = signalrConnectionBuilder.shouldSkipNegotiate(true);
        signalrConnectionBuilder = signalrConnectionBuilder.shouldSkipNegotiate(true);
        signalrConnection = signalrConnectionBuilder.build();

        try
        {
            signalrConnection.on(NOTIFICATION_HUB, (message) -> {
                handleEvent(message);
            }, String.class);
            signalrConnection.onClosed((consumer) -> {
                try {
                    handleDisconnect(consumer);
                } catch (SafeguardEventListenerDisconnectedException ex) {
                    Logger.getLogger(SafeguardEventListener.class.getName()).log(Level.SEVERE, null, ex);
                }
            });
            signalrConnection.start();
//            signalrConnection.start(this.ignoreSsl ? new IgnoreSslValidationHttpClient() : new DefaultHttpClient()).Wait();
            this.isStarted = true;
            
        for (int x = 0; x < 5; x++) {
            HubConnectionState state = signalrConnection.getConnectionState();
            try {
                Thread.sleep(1000);
            } catch (InterruptedException ex1) {
            }
        }

            
        }
        catch (Exception ex)
        {
            throw new SafeguardForJavaException("Failure starting SignalR", ex);
        }
    }

    public void stop() throws ObjectDisposedException, SafeguardForJavaException
    {
        if (disposed)
            throw new ObjectDisposedException("SafeguardEventListener");
        try
        {
            isStarted = false;
            if (signalrConnection != null)
                signalrConnection.stop();
            cleanupConnection();
        }
        catch (Exception ex)
        {
            throw new SafeguardForJavaException("Failure stopping SignalR", ex);
        }
    }

    @Override
    public void dispose()
    {
        cleanupConnection();
        if (this.accessToken != null)
            Arrays.fill(this.accessToken, '0');
//        if (this.clientCertificate != null)
//            this.clientCertificate = null;
        if (this.apiKey != null)
            Arrays.fill(this.apiKey, '0');
        disposed = true;
    }
    
    @Override
    protected void finalize() throws Throwable {
        try {
            cleanupConnection();
            if (this.accessToken != null)
                Arrays.fill(this.accessToken, '0');
//            if (this.clientCertificate != null)
//                this.clientCertificate = null;
            if (this.apiKey != null)
                Arrays.fill(this.apiKey, '0');
        } finally {
            disposed = true;
        }
    }
}

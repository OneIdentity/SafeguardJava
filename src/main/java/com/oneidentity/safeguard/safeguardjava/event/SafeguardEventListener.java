package com.oneidentity.safeguard.safeguardjava.event;

import com.google.gson.JsonElement;
import com.microsoft.signalr.HubConnection;
import com.microsoft.signalr.HttpHubConnectionBuilder;
import com.microsoft.signalr.HubConnectionBuilder;
import com.microsoft.signalr.Action1;
import com.microsoft.signalr.OnClosedCallback;
import com.oneidentity.safeguard.safeguardjava.data.CertificateContext;
import com.oneidentity.safeguard.safeguardjava.data.SafeguardEventListenerState;
import com.oneidentity.safeguard.safeguardjava.exceptions.ArgumentException;
import com.oneidentity.safeguard.safeguardjava.exceptions.ObjectDisposedException;
import com.oneidentity.safeguard.safeguardjava.exceptions.SafeguardEventListenerDisconnectedException;
import com.oneidentity.safeguard.safeguardjava.exceptions.SafeguardForJavaException;
import io.reactivex.rxjava3.core.Single;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import okhttp3.Protocol;
import okhttp3.OkHttpClient.Builder;

class DefaultDisconnectHandler implements IDisconnectHandler {

    @Override
    public void func() throws SafeguardEventListenerDisconnectedException {
        throw new SafeguardEventListenerDisconnectedException();
    }
}

public class SafeguardEventListener implements ISafeguardEventListener, AutoCloseable {

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
    private ISafeguardEventListenerStateCallback eventListenerStateCallback;

    private HubConnection signalrConnection = null;
    private static final String NOTIFICATION_HUB = "signalr";

    private SafeguardEventListener(String eventUrl, boolean ignoreSsl, HostnameVerifier validationCallback) {
        this.eventUrl = String.format("%s/%s", eventUrl, NOTIFICATION_HUB);
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
            this.apiKeys.add(key.clone());
        if (this.apiKeys.isEmpty())
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
            this.apiKeys.add(key.clone());
        if (this.apiKeys.isEmpty())
            throw new ArgumentException("The apiKeys parameter must include at least one item");
    }

    public void setDisconnectHandler(IDisconnectHandler handler) {
        this.disconnectHandler = handler;
    }

    public void setEventHandlerRegistry(EventHandlerRegistry registry) {
        this.eventHandlerRegistry = registry;
    }

    private boolean _isStarted = false;
    @Override
    public boolean isStarted() {
        return _isStarted;
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
    public void SetEventListenerStateCallback(ISafeguardEventListenerStateCallback eventListenerStateCallback)
    {
        this.eventListenerStateCallback = eventListenerStateCallback;
    }

    @Override
    public void start() throws ObjectDisposedException, SafeguardForJavaException, SafeguardEventListenerDisconnectedException {
        if (disposed) {
            throw new ObjectDisposedException("SafeguardEventListener");
        }
        cleanupConnection();

        _isStarted = true;

        // Create and configure the connection
        signalrConnection = CreateConnection(eventUrl);

        // Subscribe to hub methods
        signalrConnection.on("NotifyEventAsync", (message) -> {
            handleEvent(message);
        }, JsonElement.class);

        // Handle error / disconnect
        signalrConnection.onClosed(new OnClosedCallback() {
            @Override
            public void invoke(Exception exception){
                try {
                    if(exception != null) {
                        Logger.getLogger(SafeguardEventListener.class.getName()).log(Level.WARNING, "SignalR error detected!", exception);
                    }
                    handleDisconnect();
                } catch (SafeguardEventListenerDisconnectedException ex) {
                    Logger.getLogger(SafeguardEventListener.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
        });

        // Start the connection
        try{
            signalrConnection.start().blockingAwait();
            CallEventListenerStateCallback(SafeguardEventListenerState.Connected);
        }
        catch(Exception error) {
            throw new SafeguardForJavaException(String.format("Failed to start signalr connection: %s", error.getMessage()), error);
        }
    }

    @Override
    public void stop() throws ObjectDisposedException, SafeguardForJavaException {
        if (disposed) {
            throw new ObjectDisposedException("SafeguardEventListener");
        }
        try {
            cleanupConnection();
        } catch (Exception ex) {
            throw new SafeguardForJavaException("Failure stopping SignalR.", ex);
        }
    }

    @Override
    public void close() throws Exception {
        dispose();
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

    private void handleEvent(JsonElement eventObject) {
        eventHandlerRegistry.handleEvent(eventObject);
    }

    private void handleDisconnect() throws SafeguardEventListenerDisconnectedException {
        if(!this.isStarted()) {
            return;
        }
        Logger.getLogger(EventHandlerRegistry.class.getName()).log(Level.WARNING, "SignalR disconnect detected, calling handler...");
        CallEventListenerStateCallback(SafeguardEventListenerState.Disconnected);
        disconnectHandler.func();
    }
    
    private void CallEventListenerStateCallback(SafeguardEventListenerState newState)
    {
        if (eventListenerStateCallback != null) {
            try {
                eventListenerStateCallback.onEventListenerStateChange(newState);
            }
            catch(Exception e)
            {
                // Just in case the user's callback function throws an exception.
            }
        }
    }

    private void cleanupConnection() {
        try {
            _isStarted = false;
            if(signalrConnection != null){
                signalrConnection.stop().blockingAwait();
                signalrConnection.close();
            }
        } finally {
            signalrConnection = null;
        }
    }

    private HubConnection CreateConnection(String eventUrl) throws SafeguardForJavaException {
        HttpHubConnectionBuilder builder = HubConnectionBuilder.create(eventUrl);

        if(accessToken != null) {
            builder.withAccessTokenProvider(Single.just(new String(accessToken)));
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

            builder.withHeader("Authorization", String.format("A2A %s", authKey));            
        }

        builder.setHttpClientBuilderCallback(new Action1<Builder>(){
            @Override
            public void invoke(Builder builder) {
                ConfigureHttpClientBuilder(builder);
            }
        });

        return builder.build();
    }

    private void ConfigureHttpClientBuilder(Builder builder)
    {
        // Set the hostname verifier
        if(validationCallback != null) {
            builder.hostnameVerifier(validationCallback);
        }

        KeyManager[] km = null;
        if(clientCertificate != null && 
                (clientCertificate.getCertificateData() != null || clientCertificate.getCertificatePath() != null)){
            
            // If we have a client certificate, set it into the KeyStore/KeyManager
            try{
                KeyStore keyStore = KeyStore.getInstance("PKCS12");
                InputStream inputStream = clientCertificate.getCertificatePath() != null ? new FileInputStream(clientCertificate.getCertificatePath()) 
                            : new ByteArrayInputStream(clientCertificate.getCertificateData());

                keyStore.load(inputStream, clientCertificate.getCertificatePassword());

                KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
                keyManagerFactory.init(keyStore, clientCertificate.getCertificatePassword());
                km = keyManagerFactory.getKeyManagers();

                // when we send a client certificate singlar resets the stream
                // and requires 1.1. No idea why. okhttp3 doesn't handle this reset 
                // automatically so the only option is to restrict the client to 1.1
                builder.protocols(Arrays.asList(Protocol.HTTP_1_1));
            }
            catch(Exception error)
            {
                String msg = String.format("Error setting client authentication certificate: %s", error.getMessage());
                Logger.getLogger(SafeguardEventListener.class.getName()).log(Level.SEVERE, msg);
            }
        }

        try{
            TrustManager[] tm = null;
            X509TrustManager x509tm = null;
            if(ignoreSsl) {
                // If IgnoreSsl, then allow all certs
                tm = _trustAllCerts;
                x509tm = (X509TrustManager)_trustAllCerts[0];
            } else {
                // Use the default trust manager
                TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(
                    TrustManagerFactory.getDefaultAlgorithm());
                trustManagerFactory.init((KeyStore) null);
                tm = trustManagerFactory.getTrustManagers();
                if (tm.length != 1 || !(tm[0] instanceof X509TrustManager)) {
                    throw new IllegalStateException("Unexpected default trust managers:" + Arrays.toString(tm));
                }
                x509tm = (X509TrustManager) tm[0];        
            }

            // Configure the SSL Context according to options and set the 
            // OkHttpClient builder SSL socket factory
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(km, tm, null);
            builder.sslSocketFactory(sslContext.getSocketFactory(), x509tm);        
        }
        catch(NoSuchAlgorithmException ex) {
            Logger.getLogger(SafeguardEventListener.class.getName()).log(Level.SEVERE, ex.getMessage());
        }
        catch(KeyManagementException ex){
            Logger.getLogger(SafeguardEventListener.class.getName()).log(Level.SEVERE, ex.getMessage());
        }
        catch(KeyStoreException ex){
            Logger.getLogger(SafeguardEventListener.class.getName()).log(Level.SEVERE, ex.getMessage());
        }
    }

    TrustManager[] _trustAllCerts = new TrustManager[]{
        new X509TrustManager() {
            @Override
            public void checkClientTrusted(java.security.cert.X509Certificate[] chain,
                                           String authType) throws java.security.cert.CertificateException {
            }

            @Override
            public void checkServerTrusted(java.security.cert.X509Certificate[] chain,
                                           String authType) throws java.security.cert.CertificateException {
            }

            @Override
            public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                return new java.security.cert.X509Certificate[0];
            }
        }
    };
}

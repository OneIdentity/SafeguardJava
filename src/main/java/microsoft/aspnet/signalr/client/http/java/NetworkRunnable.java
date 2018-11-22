/*
Copyright (c) Microsoft Open Technologies, Inc.
All Rights Reserved
See License.txt in the project root for license information.
*/

package microsoft.aspnet.signalr.client.http.java;

import com.oneidentity.safeguard.safeguardjava.restclient.RestClient;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStreamWriter;
import java.net.HttpURLConnection;
import java.net.Socket;
import java.net.URL;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;

import microsoft.aspnet.signalr.client.LogLevel;
import microsoft.aspnet.signalr.client.Logger;
import microsoft.aspnet.signalr.client.http.HttpConnectionFuture;
import microsoft.aspnet.signalr.client.http.Request;
import microsoft.aspnet.signalr.client.http.StreamResponse;
import microsoft.aspnet.signalr.client.http.HttpConnectionFuture.ResponseCallback;

/**
 * Runnable that executes a network operation
 */
class NetworkRunnable implements Runnable {

    HttpURLConnection mConnection = null;
    InputStream mResponseStream = null;
    Logger mLogger;
    Request mRequest;
    HttpConnectionFuture mFuture;
    ResponseCallback mCallback;
    String mClientCertificatePath = null;
    char[] mClientCertificatePassword = null;
    boolean mIgnoreSsl = false;

    Object mCloseLock = new Object();
    
    static final TrustManager[] trustAllCerts = new TrustManager[]{
        new X509TrustManager() {
            @Override
            public void checkClientTrusted(java.security.cert.X509Certificate[] chain, String authType) throws CertificateException {
            }

            @Override
            public void checkServerTrusted(java.security.cert.X509Certificate[] chain, String authType) throws CertificateException {
            }

            @Override
            public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                return new java.security.cert.X509Certificate[]{};
            }
        }
    };
    

    /**
     * Initializes the network runnable
     * 
     * @param logger
     *            logger to log activity
     * @param request
     *            The request to execute
     * @param future
     *            Future for the operation
     * @param callback
     *            Callback to invoke after the request execution
     */
    private NetworkRunnable(Logger logger, Request request, HttpConnectionFuture future, ResponseCallback callback, boolean ignoreSsl) {
        mLogger = logger;
        mRequest = request;
        mFuture = future;
        mCallback = callback;
        mIgnoreSsl = ignoreSsl;
    }

    public NetworkRunnable(Logger logger, Request request, HttpConnectionFuture future, ResponseCallback callback, 
            String clientCertificatePath, char[] clientCertificatePassword, boolean ignoreSsl) {
        this(logger, request, future, callback, ignoreSsl);
        mClientCertificatePath = clientCertificatePath;
        mClientCertificatePassword = clientCertificatePassword == null ? null : clientCertificatePassword.clone();
    }
    
    @Override
    public void run() {
        try {
            int responseCode = -1;
            if (!mFuture.isCancelled()) {
                if (mRequest == null) {
                    mFuture.triggerError(new IllegalArgumentException("request"));
                    return;
                }

                mLogger.log("Execute the HTTP Request", LogLevel.Verbose);
                mRequest.log(mLogger);
                if (this.mRequest.getUrl().startsWith("https")) {
                    mConnection = createHttpsURLConnection(mRequest, mClientCertificatePath, mClientCertificatePassword, mIgnoreSsl);
                } else {
                    mConnection = createHttpURLConnection(mRequest);
                }

                mLogger.log("Request executed", LogLevel.Verbose);

                responseCode = mConnection.getResponseCode();

                if (responseCode < 400) {
                    mResponseStream = mConnection.getInputStream();
                } else {
                    mResponseStream = mConnection.getErrorStream();
                }
            }
        
            if (mResponseStream != null && !mFuture.isCancelled()) {
                mCallback.onResponse(new StreamResponse(mResponseStream, responseCode, mConnection.getHeaderFields()));
                mFuture.setResult(null);
            }
        } catch (Throwable e) {
            if (!mFuture.isCancelled()) {
                if (mConnection != null) {
                    mConnection.disconnect();
                }

                mLogger.log("Error executing request: " + e.getMessage(), LogLevel.Critical);
                mFuture.triggerError(e);
            }
        } finally {
            closeStreamAndConnection();
        }
    }

    /**
     * Closes the stream and connection, if possible
     */
    void closeStreamAndConnection() {

        try {
            if (mConnection != null) {
                mConnection.disconnect();
            }
            
            if (mResponseStream != null) {
                mResponseStream.close();
            }
        } catch (Exception e) {
        }
    }

    /**
     * Creates an HttpURLConnection
     * 
     * @param request
     *            The request info
     * @return An HttpURLConnection to execute the request
     * @throws java.io.IOException
     */
    static HttpURLConnection createHttpURLConnection(Request request) throws IOException {
        URL url = new URL(request.getUrl());
        
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setConnectTimeout(15 * 1000);
        connection.setRequestMethod(request.getVerb());

        Map<String, String> headers = request.getHeaders();

        for (String key : headers.keySet()) {
            connection.setRequestProperty(key, headers.get(key));
        }

        if (request.getContent() != null) {
            connection.setDoOutput(true);
            OutputStreamWriter out = new OutputStreamWriter(connection.getOutputStream());
            String requestContent = request.getContent();
            out.write(requestContent);
            out.close();
        }

        return connection;
    }

    /**
     * Creates an HttpsURLConnection
     * 
     * @param request
     *            The request info
     * @return An HttpsURLConnection to execute the request
     * @throws java.io.IOException
     */
    static HttpsURLConnection createHttpsURLConnection(Request request, String certificatePath, char[] certificatePassword, boolean ignoreSsl) 
            throws IOException {
        
        URL url = new URL(request.getUrl());
        
        HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
        connection.setConnectTimeout(15 * 1000);
        connection.setRequestMethod(request.getVerb());
        SSLContext sslContext = getSSLContext(certificatePath, certificatePassword, null, ignoreSsl);
        connection.setSSLSocketFactory(sslContext.getSocketFactory());

        Map<String, String> headers = request.getHeaders();

        for (String key : headers.keySet()) {
            connection.setRequestProperty(key, headers.get(key));
        }

        if (request.getContent() != null) {
            connection.setDoOutput(true);
            OutputStreamWriter out = new OutputStreamWriter(connection.getOutputStream());
            String requestContent = request.getContent();
            out.write(requestContent);
            out.close();
        }

        return connection;
    }
    
    static SSLContext getSSLContext(String keyStorePath, char[] keyStorePassword, String alias, boolean ignoreSsl) {

        TrustManager[] customTrustManager = null;
        KeyManager[] customKeyManager = null;

        if (ignoreSsl) {
            customTrustManager = trustAllCerts;
        }

        if (keyStorePath != null && keyStorePassword != null) {
            InputStream in;
            KeyStore clientKs = null;
            List<String> aliases = null;
            try {
                in = new FileInputStream(keyStorePath);
                clientKs = KeyStore.getInstance("JKS");
                clientKs.load(in, keyStorePassword);
                aliases = Collections.list(clientKs.aliases());
                in.close();
                if (alias == null && aliases != null && aliases.size() > 0)
                    alias = aliases.get(0);
            } catch (FileNotFoundException ex) {
                java.util.logging.Logger.getLogger(RestClient.class.getName()).log(Level.SEVERE, null, ex);
            } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException ex) {
                java.util.logging.Logger.getLogger(RestClient.class.getName()).log(Level.SEVERE, null, ex);
            }
        
            if (alias != null) {
                try {
                    KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509");
                    keyManagerFactory.init(clientKs, keyStorePassword);
                    customKeyManager = new KeyManager[]{new ExtendedX509KeyManager((X509KeyManager) keyManagerFactory.getKeyManagers()[0], alias)};
                } catch (NoSuchAlgorithmException | KeyStoreException | UnrecoverableKeyException ex) {
                    ex.printStackTrace();
                }
            }
        }

        SSLContext ctx = null;
        try {
            ctx = SSLContext.getInstance("TLS");
            ctx.init(customKeyManager, customTrustManager, new java.security.SecureRandom());
        } catch (java.security.GeneralSecurityException ex) {
        }
        return ctx;
    }

    static class ExtendedX509KeyManager extends X509ExtendedKeyManager {

        X509KeyManager defaultKeyManager;
        String alias;

        public ExtendedX509KeyManager(X509KeyManager inKeyManager, String alias) {
            this.defaultKeyManager = inKeyManager;
            this.alias = alias;
        }

        @Override
        public String chooseEngineClientAlias(String[] keyType,
                Principal[] issuers, SSLEngine engine) {
            return alias;
        }

        @Override
        public String chooseClientAlias(String[] strings, Principal[] prncpls, Socket socket) {
            return alias;
        }

        @Override
        public String[] getClientAliases(String string, Principal[] prncpls) {
            return defaultKeyManager.getClientAliases(string, prncpls);
        }

        @Override
        public String[] getServerAliases(String string, Principal[] prncpls) {
            return defaultKeyManager.getServerAliases(string, prncpls);
        }

        @Override
        public String chooseServerAlias(String string, Principal[] prncpls, Socket socket) {
            return defaultKeyManager.chooseServerAlias(string, prncpls, socket);
        }

        @Override
        public X509Certificate[] getCertificateChain(String string) {
            return defaultKeyManager.getCertificateChain(string);
        }

        @Override
        public PrivateKey getPrivateKey(String string) {
            return defaultKeyManager.getPrivateKey(string);
        }
    }
    
}

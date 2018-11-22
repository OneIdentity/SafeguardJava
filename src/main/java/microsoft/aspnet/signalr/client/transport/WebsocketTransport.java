/*
Copyright (c) Microsoft Open Technologies, Inc.
All Rights Reserved
See License.txt in the project root for license information.
*/

package microsoft.aspnet.signalr.client.transport;

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;

import com.google.gson.Gson;
import com.oneidentity.safeguard.safeguardjava.restclient.RestClient;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
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
import java.util.logging.Level;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;

import org.java_websocket.client.WebSocketClient;
import org.java_websocket.handshake.ServerHandshake;

import microsoft.aspnet.signalr.client.ConnectionBase;
import microsoft.aspnet.signalr.client.Logger;
import microsoft.aspnet.signalr.client.SignalRFuture;
import microsoft.aspnet.signalr.client.UpdateableCancellableFuture;
import microsoft.aspnet.signalr.client.http.HttpConnection;

/**
 * Implements the WebsocketTransport for the Java SignalR library
 * Created by stas on 07/07/14.
 */
public class WebsocketTransport extends HttpClientTransport {

    private String mPrefix;
    private static final Gson gson = new Gson();
    WebSocketClient mWebSocketClient;
    private UpdateableCancellableFuture<Void> mConnectionFuture;
    final TrustManager[] trustAllCerts = new TrustManager[]{
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
    
    
    private static final String HTTP = "http";
    private static final String HTTPS = "https";
    private static final String WS = "ws";
    private static final String WSS = "wss";


    public WebsocketTransport(Logger logger, String clientCertificatePath, char[] clientCertificatePassword, boolean ignoreSsl) {
        super(logger, clientCertificatePath, clientCertificatePassword, ignoreSsl);
    }

    public WebsocketTransport(Logger logger, HttpConnection httpConnection) {
        super(logger, httpConnection);
    }

    @Override
    public String getName() {
        return "webSockets";
    }

    @Override
    public boolean supportKeepAlive() {
        return true;
    }

    @Override
    public SignalRFuture<Void> start(ConnectionBase connection, ConnectionType connectionType, final DataResultCallback callback) {
        final String connectionString = connectionType == ConnectionType.InitialConnection ? "connect" : "reconnect";

        final String transport = getName();
        final String connectionToken = connection.getConnectionToken();
        final String messageId = connection.getMessageId() != null ? connection.getMessageId() : "";
        final String groupsToken = connection.getGroupsToken() != null ? connection.getGroupsToken() : "";
        final String connectionData = connection.getConnectionData() != null ? connection.getConnectionData() : "";


        String url = null;
        try {
//            url = formatUrl(connection.getUrl()) + connectionString + '?'
//                    + "connectionData=" + URLEncoder.encode(URLEncoder.encode(connectionData, "UTF-8"), "UTF-8")
//                    + "&connectionToken=" + URLEncoder.encode(URLEncoder.encode(connectionToken, "UTF-8"), "UTF-8")
//                    + "&groupsToken=" + URLEncoder.encode(groupsToken, "UTF-8")
//                    + "&messageId=" + URLEncoder.encode(messageId, "UTF-8")
//                    + "&transport=" + URLEncoder.encode(transport, "UTF-8");
            url = formatUrl(connection.getUrl()) + connectionString + '?'
                    + "&transport=" + URLEncoder.encode(transport, "UTF-8")
                    + "&connectionToken=" + URLEncoder.encode(connectionToken, "UTF-8")
                    + "&connectionData=" + URLEncoder.encode(connectionData, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }

        mConnectionFuture = new UpdateableCancellableFuture<>(null);

        URI uri;
        try {
            uri = new URI(url);
        } catch (URISyntaxException e) {
            e.printStackTrace();
            mConnectionFuture.triggerError(e);
            return mConnectionFuture;
        }

        mWebSocketClient = new WebSocketClient(uri, connection.getHeaders()) {
            @Override
            public void onOpen(ServerHandshake serverHandshake) {
                mConnectionFuture.setResult(null);
            }

            @Override
            public void onMessage(String s) {
                callback.onData(s);
            }

            @Override
            public void onClose(int i, String s, boolean b) {
                mWebSocketClient.close();
            }

            @Override
            public void onError(Exception e) {
                mWebSocketClient.close();
            }

//            @Override
//            public void onFragment(Framedata frame) {
//                try {
//                    String decodedString = Charsetfunctions.stringUtf8(frame.getPayloadData());
//
//                    if(decodedString.equals("]}")){
//                        return;
//                    }
//
//                    if(decodedString.endsWith(":[") || null == mPrefix){
//                        mPrefix = decodedString;
//                        return;
//                    }
//
//                    String simpleConcatenate = mPrefix + decodedString;
//
//                    if(isJSONValid(simpleConcatenate)){
//                        onMessage(simpleConcatenate);
//                    }else{
//                        String extendedConcatenate = simpleConcatenate + "]}";
//                        if (isJSONValid(extendedConcatenate)) {
//                            onMessage(extendedConcatenate);
//                        } else {
//                            log("invalid json received:" + decodedString, LogLevel.Critical);
//                        }
//                    }
//                } catch (InvalidDataException e) {
//                    e.printStackTrace();
//                }
//            }
        };
        SSLContext sslContext = getSSLContext(null);
        mWebSocketClient.setSocketFactory(sslContext.getSocketFactory());
        mWebSocketClient.connect();

        connection.closed(new Runnable() {
            @Override
            public void run() {
                mWebSocketClient.close();
            }
        });

        return mConnectionFuture;
    }

    @Override
    public SignalRFuture<Void> send(ConnectionBase connection, String data, DataResultCallback callback) {
        mWebSocketClient.send(data);
        return new UpdateableCancellableFuture<>(null);
    }

    private boolean isJSONValid(String test){
        try {
            gson.fromJson(test, Object.class);
            return true;
        } catch(com.google.gson.JsonSyntaxException ex) {
            return false;
        }
    }
    
    private String formatUrl(String url) {
        if (url.startsWith(HTTPS)) {
            url = WSS + url.substring(HTTPS.length());
        } else if (url.startsWith(HTTP)) {
            url = WS + url.substring(HTTP.length());
        }

        return url;
    }
    
    private SSLContext getSSLContext(String alias) {

        TrustManager[] customTrustManager = null;
        KeyManager[] customKeyManager = null;

        if (mIgnoreSsl) {
            customTrustManager = trustAllCerts;
        }

        if (mClientCertificatePath != null && mClientCertificatePassword != null) {
            InputStream in;
            KeyStore clientKs = null;
            List<String> aliases = null;
            try {
                in = new FileInputStream(mClientCertificatePath);
                clientKs = KeyStore.getInstance("JKS");
                clientKs.load(in, mClientCertificatePassword);
                aliases = Collections.list(clientKs.aliases());
                in.close();
                if (alias == null && aliases != null && aliases.size() > 0) {
                    alias = aliases.get(0);
                }
            } catch (FileNotFoundException ex) {
                java.util.logging.Logger.getLogger(RestClient.class.getName()).log(Level.SEVERE, null, ex);
            } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException ex) {
                java.util.logging.Logger.getLogger(RestClient.class.getName()).log(Level.SEVERE, null, ex);
            }

            if (alias != null) {
                try {
                    KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509");
                    keyManagerFactory.init(clientKs, mClientCertificatePassword);
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

    class ExtendedX509KeyManager extends X509ExtendedKeyManager {

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
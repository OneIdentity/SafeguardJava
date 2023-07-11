package com.oneidentity.safeguard.safeguardjava.restclient;

import static com.oneidentity.safeguard.safeguardjava.CertificateUtilities.WINDOWSKEYSTORE;
import com.oneidentity.safeguard.safeguardjava.IProgressCallback;
import com.oneidentity.safeguard.safeguardjava.data.CertificateContext;
import com.oneidentity.safeguard.safeguardjava.data.JsonObject;
import com.oneidentity.safeguard.safeguardjava.exceptions.SafeguardForJavaException;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.Socket;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.ConsoleHandler;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;
import org.apache.http.HttpEntity;
import org.apache.http.HttpHeaders;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.config.CookieSpecs;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.RequestBuilder;
import org.apache.http.config.Registry;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.mime.HttpMultipartMode;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.BasicHttpClientConnectionManager;
import org.apache.http.entity.StringEntity;
import org.apache.http.entity.mime.MultipartEntityBuilder;
import org.apache.http.impl.client.BasicCookieStore;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.cookie.BasicClientCookie;

public class RestClient {

    private CloseableHttpClient client = null;
    private BasicCookieStore cookieStore = new BasicCookieStore();

    private String serverUrl = null;
    private String hostDomain = null;
    private boolean ignoreSsl = false;
    private HostnameVerifier validationCallback = null;

    Logger logger = Logger.getLogger(getClass().getName());

    public RestClient(String connectionAddr, boolean ignoreSsl, HostnameVerifier validationCallback) {

        client = createClientBuilder(connectionAddr, ignoreSsl, validationCallback).build();
    }

    public RestClient(String connectionAddr, String userName, char[] password, boolean ignoreSsl, HostnameVerifier validationCallback) {
        

        HttpClientBuilder builder = createClientBuilder(connectionAddr, ignoreSsl, validationCallback);
        CredentialsProvider provider = new BasicCredentialsProvider();
        provider.setCredentials(AuthScope.ANY, new UsernamePasswordCredentials(userName, new String(password)));
        
        RequestConfig customizedRequestConfig = RequestConfig.custom().setCookieSpec(CookieSpecs.STANDARD).build();
        
        client = builder.setDefaultCredentialsProvider(provider)
                .setDefaultRequestConfig(customizedRequestConfig)
                .setDefaultCookieStore(cookieStore)
                .build();
    }

    private HttpClientBuilder createClientBuilder(String connectionAddr, boolean ignoreSsl, HostnameVerifier validationCallback) {

        // Used to produce debug output
        if (false) {
            Handler handlerObj = new ConsoleHandler();
            handlerObj.setLevel(Level.ALL);
            logger.addHandler(handlerObj);
            logger.setLevel(Level.ALL);
            logger.setUseParentHandlers(false);
        }

        this.ignoreSsl = ignoreSsl;
        this.serverUrl = connectionAddr;
        
        try {
            URL aUrl = new URL(connectionAddr);
            this.hostDomain = aUrl.getHost();
        } catch (MalformedURLException ex) {
            Logger.getLogger(RestClient.class.getName()).log(Level.SEVERE, "Invalid URL", ex);
        }

        SSLConnectionSocketFactory sslsf = null; 
        if (ignoreSsl) {
            this.validationCallback = null;
            sslsf = new SSLConnectionSocketFactory(getSSLContext(null, null, null, null), NoopHostnameVerifier.INSTANCE);
        } else if (validationCallback != null) {
            this.validationCallback = validationCallback;
            sslsf = new SSLConnectionSocketFactory(getSSLContext(null, null, null, null), validationCallback); 
        } else {
            sslsf = new SSLConnectionSocketFactory(getSSLContext(null, null, null, null));
        }
        Registry<ConnectionSocketFactory> socketFactoryRegistry = RegistryBuilder.<ConnectionSocketFactory> create().register("https", sslsf).build();
        BasicHttpClientConnectionManager connectionManager = new BasicHttpClientConnectionManager(socketFactoryRegistry);
        
        return HttpClients.custom().setSSLSocketFactory(sslsf).setConnectionManager(connectionManager);
    }
    
    private URI getBaseURI(String segments) {
        try {
            return new URI(serverUrl+"/"+segments);
        } catch (URISyntaxException ex) {
            Logger.getLogger(RestClient.class.getName()).log(Level.SEVERE, "Invalid URI", ex);
        }
        return null;
    }

    public String getBaseURL() {
        return serverUrl;
    }

    private Map<String,String> parseKeyValue(String value) {
        
        HashMap<String,String> keyValues = new HashMap<>();
        String[] parts = value.split(";");
        for (String p : parts) {
            String[] kv = p.split("=");
            if (kv.length == 1) {
                keyValues.put(kv[0].trim(), "");
            }
            if (kv.length == 2) {
                keyValues.put(kv[0].trim(), kv[1].trim());
            }
        }
        
        return keyValues;
    }
    
    public void addSessionId(String cookieValue) {
        if (cookieValue == null) {
            Logger.getLogger(RestClient.class.getName()).log(Level.SEVERE, "Session cookie cannot be null");
            return;
        }
        
        try {
            Map<String,String> keyValues = parseKeyValue(cookieValue);

            String sessionId = keyValues.get("session_id");
            if (sessionId != null) {
                BasicClientCookie cookie = new BasicClientCookie("session_id", sessionId);

                String expiryDate = keyValues.get("expires");
                if (expiryDate != null) {
                    SimpleDateFormat formatter = new SimpleDateFormat("EEE, d MMM yyyy HH:mm:ss z");
                    Date date = formatter.parse(expiryDate);
                    cookie.setExpiryDate(date);
                }

                String path = keyValues.get("Path");
                if (path != null) {
                    cookie.setPath(path);
                }

                if (this.hostDomain != null) {
                    cookie.setDomain(this.hostDomain);
                }
                
                String secure = keyValues.get("Secure");
                if (secure != null) {
                    cookie.setSecure(true);
                }

                this.cookieStore.addCookie(cookie);
            }
        }
        catch (Exception ex) {
            Logger.getLogger(RestClient.class.getName()).log(Level.SEVERE, "Failed to set session cookie.", ex);
        }
    }
    
    public CloseableHttpResponse execGET(String path, Map<String, String> queryParams, Map<String, String> headers, Integer timeout) {

        RequestBuilder rb = prepareRequest (RequestBuilder.get(getBaseURI(path)), queryParams, headers, timeout);

        try {
            CloseableHttpResponse r = client.execute(rb.build());
            return r;
        } catch (Exception ex) {
            return null;
        }
    }

    public CloseableHttpResponse execGET(String path, Map<String, String> queryParams, Map<String, String> headers, Integer timeout, CertificateContext certificateContext) {

        CloseableHttpClient certClient = getClientWithCertificate(certificateContext);

        if (certClient != null) {
            RequestBuilder rb = prepareRequest(RequestBuilder.get(getBaseURI(path)), queryParams, headers, timeout);

            try {
                CloseableHttpResponse r = certClient.execute(rb.build());
                return r;
            } catch (Exception ex) {
                return null;
            }
        }
        return null;
    }
    
    public CloseableHttpResponse execGETBytes(String path, Map<String, String> queryParams, Map<String, String> headers, 
            Integer timeout, IProgressCallback progressCallback) {

        if (headers == null || !headers.containsKey(HttpHeaders.ACCEPT)) {
            headers = headers == null ? new HashMap<>() : headers;
            headers.put(HttpHeaders.ACCEPT, "application/octet-stream");
        }
        RequestBuilder rb = prepareRequest(RequestBuilder.get(getBaseURI(path)), queryParams, headers, timeout);

        try {
            CloseableHttpResponse r = client.execute(rb.build());
            return r;
        } catch (IOException ex) {
            return null;
        }
    }
    
    public CloseableHttpResponse execGETBytes(String path, Map<String, String> queryParams, Map<String, String> headers, 
            Integer timeout, CertificateContext certificateContext, IProgressCallback progressCallback) {

        CloseableHttpClient certClient = getClientWithCertificate(certificateContext);
        
        if (certClient != null) {
            if (headers == null || !headers.containsKey(HttpHeaders.ACCEPT)) {
                headers = headers == null ? new HashMap<>() : headers;
                headers.put(HttpHeaders.ACCEPT, "application/octet-stream");
            }
            RequestBuilder rb = prepareRequest(RequestBuilder.get(getBaseURI(path)), queryParams, headers, timeout);

            try {
                CloseableHttpResponse r = client.execute(rb.build());
                return r;
            } catch (IOException ex) {
                return null;
            }
        }
        return null;
    }

    public CloseableHttpResponse execPUT(String path, Map<String, String> queryParams, Map<String, String> headers, Integer timeout, JsonObject requestEntity) {

        RequestBuilder rb = prepareRequest(RequestBuilder.put(getBaseURI(path)), queryParams, headers, timeout);

        try {
            String body = requestEntity.toJson();
            rb.setEntity(new StringEntity(body == null ? "{}" : body));
            CloseableHttpResponse r = client.execute(rb.build());
            return r;
        } catch (Exception ex) {
            return null;
        }
    }

    public CloseableHttpResponse execPUT(String path, Map<String, String> queryParams, Map<String, String> headers, Integer timeout, 
            JsonObject requestEntity, CertificateContext certificateContext) {
        CloseableHttpClient certClient = getClientWithCertificate(certificateContext);

        if (certClient != null) {
            RequestBuilder rb = prepareRequest(RequestBuilder.put(getBaseURI(path)), queryParams, headers, timeout);

            try {
                String body = requestEntity.toJson();
                rb.setEntity(new StringEntity(body == null ? "{}" : body));
                CloseableHttpResponse r = certClient.execute(rb.build());
                return r;
            } catch (Exception ex) {
                return null;
            }
        }
        return null;
    }
    
    public CloseableHttpResponse execPOST(String path, Map<String, String> queryParams, Map<String, String> headers, Integer timeout, JsonObject requestEntity) {

        RequestBuilder rb = prepareRequest(RequestBuilder.post(getBaseURI(path)), queryParams, headers, timeout);

        try {
            String body = requestEntity.toJson();
            rb.setEntity(new StringEntity(body == null ? "{}" : body));
            CloseableHttpResponse r = client.execute(rb.build());
            return r;
        } catch (Exception ex) {
            return null;
        }
    }

    public CloseableHttpResponse execPOST(String path, Map<String, String> queryParams, Map<String, String> headers, Integer timeout,
            JsonObject requestEntity, CertificateContext certificateContext) throws SafeguardForJavaException {

        CloseableHttpClient certClient = getClientWithCertificate(certificateContext);

        if (certClient != null) {
            RequestBuilder rb = prepareRequest(RequestBuilder.post(getBaseURI(path)), queryParams, headers, timeout);

            try {
                String body = requestEntity.toJson();
                rb.setEntity(new StringEntity(body == null ? "{}" : body));
                CloseableHttpResponse r = certClient.execute(rb.build());
                return r;
            } catch (IOException ex) {
                return null;
            }
        }

        return null;
    }
    
    public CloseableHttpResponse execPOSTBytes(String path, Map<String, String> queryParams, Map<String, String> headers, Integer timeout, 
            byte[] requestEntity, IProgressCallback progressCallback) {

        if (headers == null || !headers.containsKey(HttpHeaders.CONTENT_TYPE)) {
            headers = headers == null ? new HashMap<>() : headers;
            headers.put(HttpHeaders.CONTENT_TYPE, "application/octet-stream");
        }
        RequestBuilder rb = prepareRequest(RequestBuilder.post(getBaseURI(path)), queryParams, headers, timeout);

        try {
            rb.setEntity(new ByteArrayEntity(requestEntity, progressCallback));
            CloseableHttpResponse r = client.execute(rb.build());
            return r;
        } catch (IOException ex) {
            return null;
        }
    }
    
    public CloseableHttpResponse execPOSTBytes(String path, Map<String, String> queryParams, Map<String, String> headers, Integer timeout,
            byte[] requestEntity, CertificateContext certificateContext, IProgressCallback progressCallback) {

        CloseableHttpClient certClient = getClientWithCertificate(certificateContext);

        if (certClient != null) {
            if (headers == null || !headers.containsKey(HttpHeaders.CONTENT_TYPE)) {
                headers = headers == null ? new HashMap<>() : headers;
                headers.put(HttpHeaders.CONTENT_TYPE, "application/octet-stream");
            }
            RequestBuilder rb = prepareRequest(RequestBuilder.post(getBaseURI(path)), queryParams, headers, timeout);

            try {
                rb.setEntity(new ByteArrayEntity(requestEntity, progressCallback));
                CloseableHttpResponse r = client.execute(rb.build());
                return r;
            } catch (IOException ex) {
                return null;
            }
        }
        return null;
    }

    public CloseableHttpResponse execPOSTFile(String path, Map<String, String> queryParams, Map<String, 
            String> headers, Integer timeout, String fileName) {

        File file = new File(fileName);
        
        HttpEntity data = MultipartEntityBuilder.create().setMode(HttpMultipartMode.BROWSER_COMPATIBLE)
                .addBinaryBody("firmware", file, ContentType.MULTIPART_FORM_DATA, file.getName()).build();

        if (headers == null || !headers.containsKey(HttpHeaders.CONTENT_TYPE)) {
            headers = headers == null ? new HashMap<>() : headers;
        }
        RequestBuilder rb = prepareRequest(RequestBuilder.post(getBaseURI(path)), queryParams, headers, timeout);

        try {
            rb.setEntity(data);
            CloseableHttpResponse r = client.execute(rb.build());
            return r;
        } catch (IOException ex) {
            return null;
        }
    }
    
    public CloseableHttpResponse execPOSTFile(String path, Map<String, String> queryParams, Map<String, String> headers, Integer timeout,
            String fileName, CertificateContext certificateContext) {

        CloseableHttpClient certClient = getClientWithCertificate(certificateContext);

        if (certClient != null) {
            File file = new File(fileName);
            HttpEntity data = MultipartEntityBuilder.create().setMode(HttpMultipartMode.BROWSER_COMPATIBLE)
                    .addBinaryBody("firmware", file, ContentType.MULTIPART_FORM_DATA, file.getName()).build();
            
            if (headers == null || !headers.containsKey(HttpHeaders.CONTENT_TYPE)) {
                headers = headers == null ? new HashMap<>() : headers;
            }
            RequestBuilder rb = prepareRequest(RequestBuilder.post(getBaseURI(path)), queryParams, headers, timeout);

            try {
                rb.setEntity(data);
                CloseableHttpResponse r = client.execute(rb.build());
                return r;
            } catch (IOException ex) {
                return null;
            }
        }
        return null;
    }
    
    public CloseableHttpResponse execDELETE(String path, Map<String, String> queryParams, Map<String, String> headers, Integer timeout) {

        RequestBuilder rb = prepareRequest(RequestBuilder.delete(getBaseURI(path)), queryParams, headers, timeout);

        try {
            CloseableHttpResponse r = client.execute(rb.build());
            return r;
        } catch (Exception ex) {
            return null;
        }
    }

    private CloseableHttpClient getClientWithCertificate(CertificateContext certificateContext) {

        CloseableHttpClient certClient = null;
        if (certificateContext.getCertificatePath() != null 
                || certificateContext.getCertificateData() != null 
                || certificateContext.getCertificateThumbprint() != null) {

            InputStream in;
            KeyStore clientKs = null;
            List<String> aliases = null;
            char[] keyPass = certificateContext.getCertificatePassword();
            String certificateAlias = certificateContext.getCertificateAlias();
            try {
                if (certificateContext.isWindowsKeyStore()) {
                    clientKs = KeyStore.getInstance(WINDOWSKEYSTORE);
                    clientKs.load(null, null);
                    aliases = new ArrayList<>();
                    aliases = Collections.list(clientKs.aliases());
                } else {
                    in = certificateContext.getCertificatePath() != null ? new FileInputStream(certificateContext.getCertificatePath()) 
                            : new ByteArrayInputStream(certificateContext.getCertificateData());
                    try {
                        clientKs = KeyStore.getInstance("JKS");
                    } catch (KeyStoreException ex) {
                        Logger.getLogger(RestClient.class.getName()).log(Level.SEVERE, "Could not get instance of JDK, trying PKCS12", ex);
                        clientKs = KeyStore.getInstance("PKCS12");
                    }
                    clientKs.load(in, keyPass);
                    aliases = Collections.list(clientKs.aliases());
                    in.close();
                }
            } catch (FileNotFoundException ex) {
                Logger.getLogger(RestClient.class.getName()).log(Level.SEVERE, null, ex);
            } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException ex) {
                Logger.getLogger(RestClient.class.getName()).log(Level.SEVERE, null, ex);
            }

            SSLConnectionSocketFactory sslsf = null; 
            if (ignoreSsl) {
                sslsf = new SSLConnectionSocketFactory(getSSLContext(clientKs, keyPass, certificateAlias == null ? aliases.get(0) : certificateAlias, certificateContext), NoopHostnameVerifier.INSTANCE);
            } else if (validationCallback != null) {
                sslsf = new SSLConnectionSocketFactory(getSSLContext(clientKs, keyPass, certificateAlias == null ? aliases.get(0) : certificateAlias, certificateContext), validationCallback); 
            } else {
                sslsf = new SSLConnectionSocketFactory(getSSLContext(clientKs, keyPass, certificateAlias == null ? aliases.get(0) : certificateAlias, certificateContext));
            }
            Registry<ConnectionSocketFactory> socketFactoryRegistry = RegistryBuilder.<ConnectionSocketFactory> create().register("https", sslsf).build();
            BasicHttpClientConnectionManager connectionManager = new BasicHttpClientConnectionManager(socketFactoryRegistry);
            certClient = HttpClients.custom().setSSLSocketFactory(sslsf).setConnectionManager(connectionManager).build();
        }

        return certClient;
    }

    private RequestBuilder prepareRequest(RequestBuilder rb, Map<String, String> queryParams, Map<String, String> headers, Integer timeout) {
        
        if (headers == null || !headers.containsKey(HttpHeaders.ACCEPT))
            rb.addHeader(HttpHeaders.ACCEPT, "application/json");
        if (headers == null || !headers.containsKey(HttpHeaders.CONTENT_TYPE))
            rb.addHeader(HttpHeaders.CONTENT_TYPE, "application/json");
        
        if (headers != null) {
            headers.entrySet().forEach((entry) -> {
                rb.addHeader(entry.getKey(), entry.getValue());
            });
        }
        if (queryParams != null) {
            queryParams.entrySet().forEach((entry) -> {
                rb.addParameter(entry.getKey(), entry.getValue());
            });
        }
        if (timeout != null) {
            RequestConfig rconfig = RequestConfig.custom()
                .setConnectTimeout(timeout)
                .setConnectionRequestTimeout(timeout)
                .setSocketTimeout(timeout).build();
            rb.setConfig(rconfig);
        }
        return rb;
    }

    private SSLContext getSSLContext(KeyStore keyStorePath, char[] keyStorePassword, String alias, CertificateContext certificateContext) {

        TrustManager[] customTrustManager = null;
        KeyManager[] customKeyManager = null;

        if (ignoreSsl || validationCallback != null) {
            customTrustManager = new TrustManager[]{new X509TrustManager() {
                @Override
                public void checkClientTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {
                }

                @Override
                public void checkServerTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {
                }

                @Override
                public X509Certificate[] getAcceptedIssuers() {
                    return new X509Certificate[0];
                }
            }};
        }

        if ((keyStorePath != null && keyStorePassword != null && alias != null) || (keyStorePath != null && certificateContext.isWindowsKeyStore())) {
            try {
                KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509");
                keyManagerFactory.init(keyStorePath, keyStorePassword);
                customKeyManager = new KeyManager[]{new SafeguardExtendedX509KeyManager((X509KeyManager) keyManagerFactory.getKeyManagers()[0], alias)};
            } catch (NoSuchAlgorithmException | KeyStoreException | UnrecoverableKeyException ex) {
                ex.printStackTrace();
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

    class SafeguardExtendedX509KeyManager extends X509ExtendedKeyManager {

        X509KeyManager defaultKeyManager;
        String alias;

        public SafeguardExtendedX509KeyManager(X509KeyManager inKeyManager, String alias) {
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

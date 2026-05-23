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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;
import org.apache.hc.core5.http.HttpEntity;
import org.apache.hc.core5.http.HttpHeaders;
import org.apache.hc.client5.http.auth.AuthScope;
import org.apache.hc.client5.http.auth.UsernamePasswordCredentials;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;
import org.apache.hc.core5.http.io.support.ClassicRequestBuilder;
import org.apache.hc.core5.http.config.Registry;
import org.apache.hc.core5.http.config.RegistryBuilder;
import org.apache.hc.client5.http.socket.ConnectionSocketFactory;
import org.apache.hc.client5.http.ssl.NoopHostnameVerifier;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactory;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.client5.http.entity.mime.HttpMultipartMode;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.BasicHttpClientConnectionManager;
import org.apache.hc.core5.http.io.entity.StringEntity;
import org.apache.hc.client5.http.entity.mime.MultipartEntityBuilder;
import org.apache.hc.client5.http.cookie.BasicCookieStore;
import org.apache.hc.client5.http.impl.auth.BasicCredentialsProvider;
import org.apache.hc.client5.http.impl.classic.HttpClientBuilder;
import org.apache.hc.client5.http.impl.cookie.BasicClientCookie;
import org.apache.hc.client5.http.protocol.HttpClientContext;
import org.apache.hc.core5.util.Timeout;

public class RestClient {

    /** Default timeout in milliseconds for HTTP requests (100 seconds, matching SafeguardDotNet). */
    public static final int DEFAULT_TIMEOUT_MS = 100_000;

    /**
     * Minimum TLS protocol version pinned at the SDK layer.
     *
     * <p>Hard-pinning to {@code TLSv1.2} avoids the {@code "TLS"} alias, which
     * the JRE may resolve to TLS 1.0 or 1.1 on misconfigured JVMs. TLS 1.2 is
     * the project's Java 8 baseline minimum and is widely supported by
     * Safeguard appliances. TLS 1.3 negotiation, when supported by both peers,
     * is still permitted by the underlying SSLContext.
     */
    static final String TLS_PROTOCOL = "TLSv1.2";

    private CloseableHttpClient client = null;
    private BasicCookieStore cookieStore = new BasicCookieStore();

    private String serverUrl = null;
    private String hostDomain = null;
    private boolean ignoreSsl = false;
    private HostnameVerifier validationCallback = null;

    private static final Logger logger = LoggerFactory.getLogger(RestClient.class);

    public RestClient(String connectionAddr, boolean ignoreSsl, HostnameVerifier validationCallback) {

        client = createClientBuilder(connectionAddr, ignoreSsl, validationCallback).build();
    }

    public RestClient(String connectionAddr, String userName, char[] password, boolean ignoreSsl, HostnameVerifier validationCallback) {


        HttpClientBuilder builder = createClientBuilder(connectionAddr, ignoreSsl, validationCallback);
        BasicCredentialsProvider provider = new BasicCredentialsProvider();
        provider.setCredentials(new AuthScope(null, -1), new UsernamePasswordCredentials(userName, password));

        client = builder.setDefaultCredentialsProvider(provider)
                .setDefaultCookieStore(cookieStore)
                .build();
    }

    private HttpClientBuilder createClientBuilder(String connectionAddr, boolean ignoreSsl, HostnameVerifier validationCallback) {

        // Used to produce debug output - enable SLF4J debug level instead
        if (false) {
            // Debug logging is now controlled via SLF4J configuration
        }

        this.ignoreSsl = ignoreSsl;
        this.serverUrl = connectionAddr;

        try {
            URL aUrl = new URL(connectionAddr);
            this.hostDomain = aUrl.getHost();
        } catch (MalformedURLException ex) {
            logger.error("Invalid URL", ex);
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

        return HttpClients.custom().setConnectionManager(connectionManager);
    }

    private URI getBaseURI(String segments) {
        try {
            String fullUrl = serverUrl + "/" + segments;
            int queryIdx = fullUrl.indexOf('?');
            if (queryIdx >= 0) {
                URI base = new URI(fullUrl.substring(0, queryIdx));
                String rawQuery = fullUrl.substring(queryIdx + 1);
                return new URI(base.getScheme(), base.getUserInfo(),
                        base.getHost(), base.getPort(), base.getPath(),
                        rawQuery, null);
            }
            return new URI(fullUrl);
        } catch (URISyntaxException ex) {
            logger.error("Invalid URI", ex);
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
            logger.error("Session cookie cannot be null");
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
                    cookie.setExpiryDate(date.toInstant());
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
            logger.error("Failed to set session cookie.", ex);
        }
    }

    public CloseableHttpResponse execGET(String path, Map<String, String> queryParams, Map<String, String> headers, Integer timeout) {

        ClassicRequestBuilder rb = prepareRequest(ClassicRequestBuilder.get(getBaseURI(path)), queryParams, headers);

        try {
            CloseableHttpResponse r = client.execute(rb.build(), createContext(timeout));
            return r;
        } catch (Exception ex) {
            return null;
        }
    }

    public CloseableHttpResponse execGET(String path, Map<String, String> queryParams, Map<String, String> headers, Integer timeout, CertificateContext certificateContext) {

        CloseableHttpClient certClient = getClientWithCertificate(certificateContext);

        if (certClient != null) {
            ClassicRequestBuilder rb = prepareRequest(ClassicRequestBuilder.get(getBaseURI(path)), queryParams, headers);

            try {
                CloseableHttpResponse r = certClient.execute(rb.build(), createContext(timeout));
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
        ClassicRequestBuilder rb = prepareRequest(ClassicRequestBuilder.get(getBaseURI(path)), queryParams, headers);

        try {
            CloseableHttpResponse r = client.execute(rb.build(), createContext(timeout));
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
            ClassicRequestBuilder rb = prepareRequest(ClassicRequestBuilder.get(getBaseURI(path)), queryParams, headers);

            try {
                CloseableHttpResponse r = client.execute(rb.build(), createContext(timeout));
                return r;
            } catch (IOException ex) {
                return null;
            }
        }
        return null;
    }

    public CloseableHttpResponse execPUT(String path, Map<String, String> queryParams, Map<String, String> headers, Integer timeout, JsonObject requestEntity) {

        ClassicRequestBuilder rb = prepareRequest(ClassicRequestBuilder.put(getBaseURI(path)), queryParams, headers);

        try {
            String body = requestEntity.toJson();
            rb.setEntity(new StringEntity(body == null ? "{}" : body));
            CloseableHttpResponse r = client.execute(rb.build(), createContext(timeout));
            return r;
        } catch (Exception ex) {
            return null;
        }
    }

    public CloseableHttpResponse execPUT(String path, Map<String, String> queryParams, Map<String, String> headers, Integer timeout,
            JsonObject requestEntity, CertificateContext certificateContext) {
        CloseableHttpClient certClient = getClientWithCertificate(certificateContext);

        if (certClient != null) {
            ClassicRequestBuilder rb = prepareRequest(ClassicRequestBuilder.put(getBaseURI(path)), queryParams, headers);

            try {
                String body = requestEntity.toJson();
                rb.setEntity(new StringEntity(body == null ? "{}" : body));
                CloseableHttpResponse r = certClient.execute(rb.build(), createContext(timeout));
                return r;
            } catch (Exception ex) {
                return null;
            }
        }
        return null;
    }

    public CloseableHttpResponse execPOST(String path, Map<String, String> queryParams, Map<String, String> headers, Integer timeout, JsonObject requestEntity) {

        ClassicRequestBuilder rb = prepareRequest(ClassicRequestBuilder.post(getBaseURI(path)), queryParams, headers);

        try {
            String body = requestEntity.toJson();
            rb.setEntity(new StringEntity(body == null ? "{}" : body));
            CloseableHttpResponse r = client.execute(rb.build(), createContext(timeout));
            return r;
        } catch (Exception ex) {
            return null;
        }
    }

    public CloseableHttpResponse execPOST(String path, Map<String, String> queryParams, Map<String, String> headers, Integer timeout,
            JsonObject requestEntity, CertificateContext certificateContext) throws SafeguardForJavaException {

        CloseableHttpClient certClient = getClientWithCertificate(certificateContext);

        if (certClient != null) {
            ClassicRequestBuilder rb = prepareRequest(ClassicRequestBuilder.post(getBaseURI(path)), queryParams, headers);

            try {
                String body = requestEntity.toJson();
                rb.setEntity(new StringEntity(body == null ? "{}" : body));
                CloseableHttpResponse r = certClient.execute(rb.build(), createContext(timeout));
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
        ClassicRequestBuilder rb = prepareRequest(ClassicRequestBuilder.post(getBaseURI(path)), queryParams, headers);

        try {
            rb.setEntity(new ByteArrayEntity(requestEntity, progressCallback));
            CloseableHttpResponse r = client.execute(rb.build(), createContext(timeout));
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
            ClassicRequestBuilder rb = prepareRequest(ClassicRequestBuilder.post(getBaseURI(path)), queryParams, headers);

            try {
                rb.setEntity(new ByteArrayEntity(requestEntity, progressCallback));
                CloseableHttpResponse r = client.execute(rb.build(), createContext(timeout));
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

        HttpEntity data = MultipartEntityBuilder.create().setMode(HttpMultipartMode.LEGACY)
                .addBinaryBody("firmware", file, ContentType.MULTIPART_FORM_DATA, file.getName()).build();

        if (headers == null || !headers.containsKey(HttpHeaders.CONTENT_TYPE)) {
            headers = headers == null ? new HashMap<>() : headers;
        }
        ClassicRequestBuilder rb = prepareRequest(ClassicRequestBuilder.post(getBaseURI(path)), queryParams, headers);

        try {
            rb.setEntity(data);
            CloseableHttpResponse r = client.execute(rb.build(), createContext(timeout));
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
            HttpEntity data = MultipartEntityBuilder.create().setMode(HttpMultipartMode.LEGACY)
                    .addBinaryBody("firmware", file, ContentType.MULTIPART_FORM_DATA, file.getName()).build();

            if (headers == null || !headers.containsKey(HttpHeaders.CONTENT_TYPE)) {
                headers = headers == null ? new HashMap<>() : headers;
            }
            ClassicRequestBuilder rb = prepareRequest(ClassicRequestBuilder.post(getBaseURI(path)), queryParams, headers);

            try {
                rb.setEntity(data);
                CloseableHttpResponse r = client.execute(rb.build(), createContext(timeout));
                return r;
            } catch (IOException ex) {
                return null;
            }
        }
        return null;
    }

    public CloseableHttpResponse execDELETE(String path, Map<String, String> queryParams, Map<String, String> headers, Integer timeout) {

        ClassicRequestBuilder rb = prepareRequest(ClassicRequestBuilder.delete(getBaseURI(path)), queryParams, headers);

        try {
            CloseableHttpResponse r = client.execute(rb.build(), createContext(timeout));
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
                    try (InputStream in2 = certificateContext.getCertificatePath() != null ? new FileInputStream(certificateContext.getCertificatePath())
                            : new ByteArrayInputStream(certificateContext.getCertificateData())) {
                        try {
                            clientKs = KeyStore.getInstance("JKS");
                        } catch (KeyStoreException ex) {
                            logger.error("Could not get instance of JDK, trying PKCS12", ex);
                            clientKs = KeyStore.getInstance("PKCS12");
                        }
                        clientKs.load(in2, keyPass);
                        aliases = Collections.list(clientKs.aliases());
                    }
                }
            } catch (FileNotFoundException ex) {
                logger.error("Exception occurred", ex);
            } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException ex) {
                logger.error("Exception occurred", ex);
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
            certClient = HttpClients.custom().setConnectionManager(connectionManager).build();
        }

        return certClient;
    }

    private ClassicRequestBuilder prepareRequest(ClassicRequestBuilder rb, Map<String, String> queryParams, Map<String, String> headers) {

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
        return rb;
    }

    private HttpClientContext createContext(Integer timeout) {
        HttpClientContext context = HttpClientContext.create();
        int effectiveTimeout = (timeout != null) ? timeout : DEFAULT_TIMEOUT_MS;
        RequestConfig rconfig = RequestConfig.custom()
            .setConnectTimeout(Timeout.ofMilliseconds(effectiveTimeout))
            .setConnectionRequestTimeout(Timeout.ofMilliseconds(effectiveTimeout))
            .setResponseTimeout(Timeout.ofMilliseconds(effectiveTimeout)).build();
        context.setRequestConfig(rconfig);
        return context;
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
            ctx = SSLContext.getInstance(TLS_PROTOCOL);
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

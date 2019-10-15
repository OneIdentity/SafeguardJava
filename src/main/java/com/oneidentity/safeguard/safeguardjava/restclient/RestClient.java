package com.oneidentity.safeguard.safeguardjava.restclient;

import com.oneidentity.safeguard.safeguardjava.data.JsonObject;
import com.sun.jersey.api.client.Client;
import com.sun.jersey.api.client.ClientResponse;
import com.sun.jersey.api.client.WebResource;
import com.sun.jersey.api.client.WebResource.Builder;
import com.sun.jersey.api.client.config.ClientConfig;
import com.sun.jersey.api.client.config.DefaultClientConfig;
import com.sun.jersey.client.urlconnection.HTTPSProperties;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
import java.net.URI;
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
import java.util.logging.ConsoleHandler;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;
//import javax.ws.rs.client.Client;
//import javax.ws.rs.client.ClientBuilder;
//import javax.ws.rs.client.Entity;
//import javax.ws.rs.client.Invocation.Builder;
//import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.MediaType;
//import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;

//import org.glassfish.jersey.logging.LoggingFeature;

public class RestClient {

    private Client client = null;
    private String serverUrl = null;
    private boolean ignoreSsl = false;

    Logger logger = Logger.getLogger(getClass().getName());

    public RestClient(String connectionAddr, boolean ignoreSsl) {

        if (false) {
            Handler handlerObj = new ConsoleHandler();
            handlerObj.setLevel(Level.ALL);
            logger.addHandler(handlerObj);
            logger.setLevel(Level.ALL);
            logger.setUseParentHandlers(false);
        }

        this.ignoreSsl = ignoreSsl;
        this.serverUrl = connectionAddr;

//        ClientBuilder builder = ClientBuilder.newBuilder()
//                .sslContext(getSSLContext(null, null, null))
//                .register(new LoggingFeature(logger, Level.FINE, null, null));

        ClientConfig config = new DefaultClientConfig();
        SSLContext ctx = getSSLContext(null, null, null);
        
        HostnameVerifier hostnameVerifier = HttpsURLConnection.getDefaultHostnameVerifier();
        if (ignoreSsl) {
            HostnameVerifier allowAll = new HostnameVerifier() {
                @Override
                public boolean verify(String hostname, SSLSession session) {
                    return true;
                }
            };
//            builder.hostnameVerifier(allowAll);
        }
        config.getProperties().put(HTTPSProperties.PROPERTY_HTTPS_PROPERTIES, new HTTPSProperties(hostnameVerifier, ctx));

//        client = builder.build();
        client = Client.create(config);
    }

    private URI getBaseURI() {
        return UriBuilder.fromUri(serverUrl).build();
    }

    public String getBaseURL() {
        return serverUrl;
    }

//    public Response execGET(String path, Map<String, String> queryParams, Map<String, String> headers) {
    public ClientResponse execGET(String path, Map<String, String> queryParams, Map<String, String> headers) {

//        WebTarget service = prepareService(client, path, queryParams);
        WebResource service = prepareService(client, path, queryParams);
        Builder requestBuilder = prepareRequest(service, headers);

        try {
//            Response r = requestBuilder.get(Response.class);
            ClientResponse r = requestBuilder.get(ClientResponse.class);
            return r;
        } catch (Exception ex) {
            return null;
        }
    }

//    public Response execGET(String path, Map<String, String> queryParams, Map<String, String> headers, String certificatePath, char[] keyPass) {
    public ClientResponse execGET(String path, Map<String, String> queryParams, Map<String, String> headers, String certificatePath, char[] keyPass) {

        Client certClient = getClientWithCertificate(certificatePath, keyPass, null);

        if (certClient != null) {
//            WebTarget service = prepareService(certClient, path, queryParams);
            WebResource service = prepareService(certClient, path, queryParams);
            Builder requestBuilder = prepareRequest(service, headers);

            try {
//                Response r = requestBuilder.get(Response.class);
                ClientResponse r = requestBuilder.get(ClientResponse.class);
                return r;
            } catch (Exception ex) {
                return null;
            }
        }
        return null;
    }

//    public Response execGET(String path) {
    public ClientResponse execGET(String path) {

//        WebTarget service = client.target(path);
        WebResource service = client.resource(path);
        try {
//            Response r = service.request(MediaType.APPLICATION_JSON).get(Response.class);
            ClientResponse r = service.accept(MediaType.APPLICATION_JSON).get(ClientResponse.class);
            return r;
        } catch (Exception ex) {
            return null;
        }
    }

//    public Response execPUT(String path, Map<String, String> queryParams, Map<String, String> headers, JsonObject requestEntity) {
    public ClientResponse execPUT(String path, Map<String, String> queryParams, Map<String, String> headers, JsonObject requestEntity) {

//        WebTarget service = prepareService(client, path, queryParams);
        WebResource service = prepareService(client, path, queryParams);
        Builder requestBuilder = prepareRequest(service, headers);

        try {
//            Response r = requestBuilder.put(Entity.json(requestEntity.toJson()), Response.class);
            ClientResponse r = requestBuilder.type(MediaType.APPLICATION_JSON).put(ClientResponse.class, requestEntity.toJson());
            return r;
        } catch (Exception ex) {
            return null;
        }
    }

//    public Response execPOST(String path, Map<String, String> queryParams, Map<String, String> headers, JsonObject requestEntity) {
    public ClientResponse execPOST(String path, Map<String, String> queryParams, Map<String, String> headers, JsonObject requestEntity) {

//        WebTarget service = prepareService(client, path, queryParams);
        WebResource service = prepareService(client, path, queryParams);
        Builder requestBuilder = prepareRequest(service, headers);

        try {
//            Response r = requestBuilder.post(Entity.json(requestEntity.toJson()), Response.class);
            ClientResponse r = requestBuilder.type(MediaType.APPLICATION_JSON).post(ClientResponse.class, requestEntity.toJson());
            return r;
        } catch (Exception ex) {
            return null;
        }
    }

//    public Response execPOST(String path, Map<String, String> queryParams, Map<String, String> headers, JsonObject requestEntity, 
    public ClientResponse execPOST(String path, Map<String, String> queryParams, Map<String, String> headers, JsonObject requestEntity, 
            String certificatePath, char[] keyPass, String certificateAlias) {

        Client certClient = getClientWithCertificate(certificatePath, keyPass, certificateAlias);

        if (certClient != null) {
//            WebTarget service = prepareService(certClient, path, queryParams);
            WebResource service = prepareService(certClient, path, queryParams);
            Builder requestBuilder = prepareRequest(service, headers);

            try {
//                Response r = requestBuilder.post(Entity.json(requestEntity.toJson()), Response.class);
                ClientResponse r = requestBuilder.type(MediaType.APPLICATION_JSON).post(ClientResponse.class, requestEntity.toJson());
                return r;
            } catch (Exception ex) {
                return null;
            }
        }

        return null;
    }

//    public Response execPOSTFile(String path, String fileName, Map<String, String> queryParams, Object requestEntity) {
    public ClientResponse execPOSTFile(String path, String fileName, Map<String, String> queryParams, Object requestEntity) {

        String contentDisp = "attachment; filename=\"" + fileName + "\"";
//        WebTarget service = client.target(getBaseURI()).path(path);
        WebResource service = client.resource(getBaseURI()).path(path);

        if (queryParams == null) {
            for (Map.Entry<String, String> entry : queryParams.entrySet()) {
                service = service.queryParam(entry.getKey(), entry.getValue());
            }
        }

//        Response r = service.request(MediaType.APPLICATION_JSON).header("Content-Disposition", contentDisp).post(Entity.entity(requestEntity, MediaType.APPLICATION_OCTET_STREAM), Response.class);
        ClientResponse r = service.accept(MediaType.APPLICATION_JSON).type(MediaType.APPLICATION_OCTET_STREAM).header("Content-Disposition", contentDisp).post(ClientResponse.class, requestEntity);

        return r;
    }

//    public Response execDELETE(String path, Map<String, String> queryParams, Map<String, String> headers) {
    public ClientResponse execDELETE(String path, Map<String, String> queryParams, Map<String, String> headers) {

//        WebTarget service = prepareService(client, path, queryParams);
        WebResource service = prepareService(client, path, queryParams);
        Builder requestBuilder = prepareRequest(service, headers);

        try {
//            Response r = requestBuilder.delete(Response.class);
            ClientResponse r = requestBuilder.delete(ClientResponse.class);
            return r;
        } catch (Exception ex) {
            return null;
        }
    }

    private Client getClientWithCertificate(String certificatePath, char[] keyPass, String certificateAlias) {

        Client certClient = null;
        if (certificatePath != null) {
//            HostnameVerifier allowAll = client.getHostnameVerifier();
            HTTPSProperties httpsProperty = (HTTPSProperties)(client.getProperties().getOrDefault(HTTPSProperties.PROPERTY_HTTPS_PROPERTIES, null));

            InputStream in;
            KeyStore clientKs = null;
            List<String> aliases = null;
            try {
                in = new FileInputStream(certificatePath);
                clientKs = KeyStore.getInstance("JKS");
                clientKs.load(in, keyPass);
                aliases = Collections.list(clientKs.aliases());
                in.close();
            } catch (FileNotFoundException ex) {
                Logger.getLogger(RestClient.class.getName()).log(Level.SEVERE, null, ex);
            } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException ex) {
                Logger.getLogger(RestClient.class.getName()).log(Level.SEVERE, null, ex);
            }

//            certClient = ClientBuilder.newBuilder()
//                    .sslContext(getSSLContext(clientKs, keyPass, certificateAlias == null ? aliases.get(0) : certificateAlias))
//                    .hostnameVerifier(allowAll)
//                    .register(new LoggingFeature(logger, Level.FINE, null, null)).build();

            ClientConfig config = new DefaultClientConfig();
            SSLContext ctx = getSSLContext(clientKs, keyPass, certificateAlias == null ? aliases.get(0) : certificateAlias);

            config.getProperties().put(HTTPSProperties.PROPERTY_HTTPS_PROPERTIES, new HTTPSProperties(httpsProperty.getHostnameVerifier(), ctx));
            certClient = Client.create(config);
        }

        return certClient;
    }

//    private WebTarget prepareService(Client targetClient, String path, Map<String, String> queryParams) {
//
//        WebTarget service = targetClient.target(getBaseURI()).path(path);
//
//        if (queryParams != null) {
//            for (Map.Entry<String, String> entry : queryParams.entrySet()) {
//                service = service.queryParam(entry.getKey(), entry.getValue());
//            }
//        }
//
//        return service;
//    }
    
    private WebResource prepareService(Client targetClient, String path, Map<String, String> queryParams) {

        WebResource service = targetClient.resource(getBaseURI()).path(path);

        if (queryParams != null) {
            for (Map.Entry<String, String> entry : queryParams.entrySet()) {
                service = service.queryParam(entry.getKey(), entry.getValue());
            }
        }

        return service;
    }

//    private Builder prepareRequest(WebTarget service, Map<String, String> headers) {
//
//        Builder requestBuilder = service.request(MediaType.APPLICATION_JSON);
//
//        if (headers != null) {
//            for (Map.Entry<String, String> entry : headers.entrySet()) {
//                requestBuilder = requestBuilder.header(entry.getKey(), entry.getValue());
//            }
//        }
//        return requestBuilder;
//    }

    private Builder prepareRequest(WebResource service, Map<String, String> headers) {

        Builder requestBuilder = service.accept(MediaType.APPLICATION_JSON);

        if (headers != null) {
            for (Map.Entry<String, String> entry : headers.entrySet()) {
                requestBuilder = requestBuilder.header(entry.getKey(), entry.getValue());
            }
        }
        return requestBuilder;
    }
    
    private SSLContext getSSLContext(KeyStore keyStorePath, char[] keyStorePassword, String alias) {

        TrustManager[] customTrustManager = null;
        KeyManager[] customKeyManager = null;

        if (ignoreSsl) {
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
  
        if (keyStorePath != null && keyStorePassword != null && alias != null) {
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

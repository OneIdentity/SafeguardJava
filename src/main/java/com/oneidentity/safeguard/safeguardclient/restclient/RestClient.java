package com.oneidentity.safeguard.safeguardclient.restclient;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
import java.net.URI;
import java.security.KeyManagementException;
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
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.client.Invocation.Builder;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;
import org.glassfish.jersey.client.ClientConfig;

import org.glassfish.jersey.logging.LoggingFeature;

public class RestClient {

    private ClientConfig config = null;
    private Client client = null;
    private String SERVERURL = null;
    private TrustManager[] trustAllCerts = null;
    
    Logger logger = Logger.getLogger(getClass().getName());

    public RestClient(String connectionAddr) {

        if (false) {
            Handler handlerObj = new ConsoleHandler();
            handlerObj.setLevel(Level.ALL);
            logger.addHandler(handlerObj);
            logger.setLevel(Level.ALL);
            logger.setUseParentHandlers(false);
        }
        
        SSLContext sslContext = null;
        SERVERURL = connectionAddr;

        trustAllCerts = new TrustManager[]{new X509TrustManager() 
        {
                @Override
                public void checkClientTrusted(X509Certificate[] arg0, String arg1) throws CertificateException{}
                @Override
                public void checkServerTrusted(X509Certificate[] arg0, String arg1) throws CertificateException{}
                @Override
                public X509Certificate[] getAcceptedIssuers()
                {
                    return new X509Certificate[0];
                }
        }};            
        
        try {
            sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, trustAllCerts, new java.security.SecureRandom());            
        } catch (NoSuchAlgorithmException | KeyManagementException ex) {
            Logger.getLogger(RestClient.class.getName()).log(Level.SEVERE, null, ex);
        }

        HostnameVerifier allowAll = new HostnameVerifier() {
            @Override
            public boolean verify(String hostname, SSLSession session) {
                return true;
            }
        };
        
        client = ClientBuilder.newBuilder()
                .sslContext(sslContext)
                .hostnameVerifier(allowAll)
                .register(new LoggingFeature(logger, Level.FINE, null, null)).build();
        
    }

//    public MultivaluedMap<String,String> createMVMap(String key, String value) {
//        
//        MultivaluedMap<String,String> mvm = new MultivaluedMapImpl();
//        if (key != null) {
//            mvm.add(key, encodeValue(value));
//        }
//        return mvm;
//    }

    private URI getBaseURI() {
        return UriBuilder.fromUri(SERVERURL).build();
    }

    public String getBaseURL() {
        return SERVERURL;
    }
    
    public Response execGET(String path, Map<String,String> queryParams, Map<String,String> headers) {

        WebTarget service = prepareService(client, path, queryParams);
        Builder requestBuilder = prepareRequest(service, headers);

        Response r = requestBuilder.get(Response.class);
        return r;
    }

    public Response execGET(String path, Map<String,String> queryParams, Map<String,String> headers, String certificatePath, char[] keyPass) {

        Client certClient = getClientWithCertificate (certificatePath, keyPass);
        
        if (certClient != null) {
            WebTarget service = prepareService(certClient, path, queryParams);
            Builder requestBuilder = prepareRequest(service, headers);

            Response r = requestBuilder.get(Response.class);
            return r;
        }
        return null;
    }
    
    public Response execGET(String path) {

        WebTarget service = client.target(path);
        Response r = service.request(MediaType.APPLICATION_JSON).get(Response.class);

        return r;
    }
    
    public Response execPUT(String path, Map<String,String> queryParams, Map<String,String> headers, Object requestEntity) {

        WebTarget service = prepareService(client, path, queryParams);
        Builder requestBuilder = prepareRequest(service, headers);
        
        Response r = requestBuilder.put(Entity.json(requestEntity.toString()), Response.class);

        return r;
    }

    public Response execPOST(String path, Map<String,String> queryParams, Map<String,String> headers, Object requestEntity) {

        WebTarget service = prepareService(client, path, queryParams);
        Builder requestBuilder = prepareRequest(service, headers);

        Response r = requestBuilder.post(Entity.json(requestEntity.toString()), Response.class);
        
        return r;
    }

    public Response execPOST(String path, Map<String,String> queryParams, Map<String,String> headers, Object requestEntity, String certificatePath, char[] keyPass) {

        Client certClient = getClientWithCertificate (certificatePath, keyPass);

        if (certClient != null) {
            WebTarget service = prepareService(certClient, path, queryParams);
            Builder requestBuilder = prepareRequest(service, headers);

            Response r = requestBuilder.post(Entity.json(requestEntity.toString()), Response.class);

            return r;
        }
        
        return null;
    }
    
    public Response execPOSTFile(String path, String fileName, Map<String,String> queryParams, Object requestEntity) {

        String contentDisp = "attachment; filename=\"" + fileName + "\"";
        WebTarget service = client.target(getBaseURI()).path(path);
        
        if (queryParams == null) {
            for (Map.Entry<String,String> entry : queryParams.entrySet()) {
                service = service.queryParam(entry.getKey(), entry.getValue());   
            }
        }
        
        Response r = service.request(MediaType.APPLICATION_JSON).header("Content-Disposition", contentDisp).post(Entity.entity(requestEntity, MediaType.APPLICATION_OCTET_STREAM), Response.class);

        return r;
    }

    public Response execDELETE(String path, Map<String,String> queryParams, Map<String,String> headers) {

        WebTarget service = prepareService(client, path, queryParams);
        Builder requestBuilder = prepareRequest(service, headers);
        
        Response r = requestBuilder.delete(Response.class);

        return r;
    }

    private Client getClientWithCertificate (String certificatePath, char[] keyPass) {
        
        Client certClient = null;
        if (certificatePath != null) {
            HostnameVerifier allowAll = client.getHostnameVerifier();
            
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
            } catch (KeyStoreException ex) {
                Logger.getLogger(RestClient.class.getName()).log(Level.SEVERE, null, ex);
            } catch (IOException ex) {
                Logger.getLogger(RestClient.class.getName()).log(Level.SEVERE, null, ex);
            } catch (NoSuchAlgorithmException ex) {
                Logger.getLogger(RestClient.class.getName()).log(Level.SEVERE, null, ex);
            } catch (CertificateException ex) {
                Logger.getLogger(RestClient.class.getName()).log(Level.SEVERE, null, ex);
            }

            
            certClient = ClientBuilder.newBuilder()
                    .sslContext(getSSLContext(clientKs, keyPass, aliases))
                    .hostnameVerifier(allowAll)
                    .register(new LoggingFeature(logger, Level.FINE, null, null)).build();
        }
        
        return certClient;
    }
    
    private WebTarget prepareService(Client targetClient, String path, Map<String,String> queryParams) {
        
        WebTarget service = targetClient.target(getBaseURI()).path(path);
        
        if (queryParams != null) {
            for (Map.Entry<String,String> entry : queryParams.entrySet()) {
                service = service.queryParam(entry.getKey(), entry.getValue());   
            }
        }
        
        return service;
    }

    private Builder prepareRequest(WebTarget service, Map<String,String> headers) {
        
        Builder requestBuilder = service.request(MediaType.APPLICATION_JSON);
        
        if (headers != null) {
            for (Map.Entry<String,String> entry : headers.entrySet()) {
                requestBuilder = requestBuilder.header(entry.getKey(), entry.getValue());   
            }
        }
        return requestBuilder;
    }
    
    private SSLContext getSSLContext(KeyStore keyStorePath, char[] keyStorePassword, List<String> aliases) {

        MyExtendedX509KeyManager customKeyManager = null;
        String alias = null;

        try {
            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509");
            keyManagerFactory.init(keyStorePath, keyStorePassword);
            if (aliases != null) {
                alias = aliases.get(0);
            }
            customKeyManager = new MyExtendedX509KeyManager((X509KeyManager) keyManagerFactory.getKeyManagers()[0], alias); 
        } catch (Exception ex) {
            ex.printStackTrace();
        }

        SSLContext ctx = null;
        try {
            ctx = SSLContext.getInstance("TLS");
            ctx.init(new KeyManager[] {customKeyManager}, trustAllCerts, null);
        } catch (java.security.GeneralSecurityException ex) {
        }
        return ctx;
    }

    class MyExtendedX509KeyManager extends X509ExtendedKeyManager {

        X509KeyManager defaultKeyManager;
        String alias;

        public MyExtendedX509KeyManager(X509KeyManager inKeyManager, String alias) {
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
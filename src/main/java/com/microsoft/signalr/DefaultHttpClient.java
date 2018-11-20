// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.
package com.microsoft.signalr;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import io.reactivex.Single;
import io.reactivex.subjects.SingleSubject;
import java.net.Socket;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
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
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.Cookie;
import okhttp3.CookieJar;
import okhttp3.HttpUrl;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import okhttp3.ResponseBody;

final class DefaultHttpClient extends HttpClient {

    private boolean ignoreSsl;
    private final OkHttpClient client;
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

    public DefaultHttpClient(boolean ignoreSsl) {
        this.ignoreSsl = ignoreSsl;
        
        OkHttpClient.Builder builder = new OkHttpClient.Builder().cookieJar(new CookieJar() {
            private List<Cookie> cookieList = new ArrayList<>();
            private Lock cookieLock = new ReentrantLock();

            @Override
            public void saveFromResponse(HttpUrl url, List<Cookie> cookies) {
                cookieLock.lock();
                try {
                    for (Cookie cookie : cookies) {
                        boolean replacedCookie = false;
                        for (int i = 0; i < cookieList.size(); i++) {
                            Cookie innerCookie = cookieList.get(i);
                            if (cookie.name().equals(innerCookie.name()) && innerCookie.matches(url)) {
                                // We have a new cookie that matches an older one so we replace the older one.
                                cookieList.set(i, innerCookie);
                                replacedCookie = true;
                                break;
                            }
                        }
                        if (!replacedCookie) {
                            cookieList.add(cookie);
                        }
                    }
                } finally {
                    cookieLock.unlock();
                }
            }

            @Override
            public List<Cookie> loadForRequest(HttpUrl url) {
                cookieLock.lock();
                try {
                    List<Cookie> matchedCookies = new ArrayList<>();
                    List<Cookie> expiredCookies = new ArrayList<>();
                    for (Cookie cookie : cookieList) {
                        if (cookie.expiresAt() < System.currentTimeMillis()) {
                            expiredCookies.add(cookie);
                        } else if (cookie.matches(url)) {
                            matchedCookies.add(cookie);
                        }
                    }

                    cookieList.removeAll(expiredCookies);
                    return matchedCookies;
                } finally {
                    cookieLock.unlock();
                }
            }
        });

        if (ignoreSsl) {
            SSLContext sslContext = getSSLContext(null, null, null);
            builder.sslSocketFactory(sslContext.getSocketFactory(), (X509TrustManager) trustAllCerts[0]);
            builder.hostnameVerifier(new HostnameVerifier() {
                @Override
                public boolean verify(String hostname, SSLSession session) {
                    return true;
                }
            });
        }
        this.client = builder.build();
    }

    @Override
    public Single<HttpResponse> send(HttpRequest httpRequest) {
        Request.Builder requestBuilder = new Request.Builder().url(httpRequest.getUrl());

        switch (httpRequest.getMethod()) {
            case "GET":
                requestBuilder.get();
                break;
            case "POST":
                RequestBody body = RequestBody.create(null, new byte[]{});
                requestBuilder.post(body);
                break;
            case "DELETE":
                requestBuilder.delete();
                break;
        }

        if (httpRequest.getHeaders() != null) {
            Collection<String> keys = httpRequest.getHeaders().keySet();
            for (String key : keys) {
                requestBuilder.addHeader(key, httpRequest.getHeaders().get(key));
            }
        }

        Request request = requestBuilder.build();

        SingleSubject<HttpResponse> responseSubject = SingleSubject.create();

        client.newCall(request).enqueue(new Callback() {
            @Override
            public void onFailure(Call call, IOException e) {
                Throwable cause = e.getCause();
                if (cause == null) {
                    cause = e;
                }
                responseSubject.onError(cause);
            }

            @Override
            public void onResponse(Call call, Response response) throws IOException {
                try (ResponseBody body = response.body()) {
                    HttpResponse httpResponse = new HttpResponse(response.code(), response.message(), body.string());
                    responseSubject.onSuccess(httpResponse);
                }
            }
        });

        return responseSubject;
    }

    @Override
    public WebSocketWrapper createWebSocket(String url, Map<String, String> headers) {
        return new OkHttpWebSocketWrapper(url, headers, client);
    }

    private SSLContext getSSLContext(KeyStore keyStorePath, char[] keyStorePassword, String alias) {

        TrustManager[] customTrustManager = null;
        KeyManager[] customKeyManager = null;

        if (ignoreSsl) {
            customTrustManager = trustAllCerts;
        }

        if (keyStorePath != null && keyStorePassword != null && alias != null) {
            try {
                KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509");
                keyManagerFactory.init(keyStorePath, keyStorePassword);
                customKeyManager = new KeyManager[]{new ExtendedX509KeyManager((X509KeyManager) keyManagerFactory.getKeyManagers()[0], alias)};
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

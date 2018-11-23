/*
Copyright (c) Microsoft Open Technologies, Inc.
All Rights Reserved
See License.txt in the project root for license information.
*/

package microsoft.aspnet.signalr.client.http.java;

import microsoft.aspnet.signalr.client.*;
import microsoft.aspnet.signalr.client.http.*;
import microsoft.aspnet.signalr.client.http.HttpConnectionFuture.ResponseCallback;

/**
 * Java HttpConnection implementation, based on HttpURLConnection and threads
 * async operations
 */
public class JavaHttpConnection implements HttpConnection {

    /**
     * User agent header name
     */
    private static final String USER_AGENT_HEADER = "User-Agent";

    private final Logger mLogger;
    private String mClientCertificatePath = null;
    private char[] mClientCertificatePassword = null;
    private String mClientCertificateAlias = null;
    private boolean mIgnoreSsl = false;

    /**
     * Initializes the JavaHttpConnection
     * 
     * @param logger
     *            logger to log activity
     * @param clientCertificatePath 
     *            client certificate path
     * @param clientCertificatePassword
     *            client certificate password
     * @param clientCertificateAlias
     *            client certificate alias
     * @param ignoreSsl
     *            Ignore SSL certificate verification
     */
    public JavaHttpConnection(Logger logger, String clientCertificatePath, char[] clientCertificatePassword, 
            String clientCertificateAlias, boolean ignoreSsl) {
        mLogger = logger;
        mIgnoreSsl = ignoreSsl;
        mClientCertificatePath = clientCertificatePath;
        mClientCertificatePassword = clientCertificatePassword == null ? null : clientCertificatePassword.clone();
        mClientCertificateAlias = clientCertificateAlias;
    }

    @Override
    public HttpConnectionFuture execute(final Request request, final ResponseCallback callback) {

        request.addHeader(USER_AGENT_HEADER, Platform.getUserAgent());

        mLogger.log("Create new thread for HTTP Connection", LogLevel.Verbose);

        HttpConnectionFuture future = new HttpConnectionFuture();

        final NetworkRunnable target = new NetworkRunnable(mLogger, request, future, callback, mClientCertificatePath, 
                mClientCertificatePassword, mClientCertificateAlias, mIgnoreSsl);
        final NetworkThread networkThread = new NetworkThread(target) {
            @Override
            void releaseAndStop() {
                try {
                    target.closeStreamAndConnection();
                } catch (Throwable error) {
                }
            }
        };

        future.onCancelled(new Runnable() {

            @Override
            public void run() {
                networkThread.releaseAndStop();
            }
        });

        networkThread.start();

        return future;
    }
}

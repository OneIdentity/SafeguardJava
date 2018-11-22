/*
Copyright (c) Microsoft Open Technologies, Inc.
All Rights Reserved
See License.txt in the project root for license information.
*/

package microsoft.aspnet.signalr.client;

import java.util.Locale;

import microsoft.aspnet.signalr.client.http.HttpConnection;
import microsoft.aspnet.signalr.client.http.java.JavaHttpConnection;

/**
 * Platform specific classes and operations
 */
public class Platform {
    static boolean mPlatformVerified = false;
    static boolean mIsAndroid = false;
    static PlatformComponent mPlatformComponent = null;

    public static void loadPlatformComponent(PlatformComponent platformComponent) {
        mPlatformComponent = platformComponent;
    }

    /**
     * Creates an adequate HttpConnection for the current platform
     * 
     * @param logger
     *            Logger to use with the connection
     * @return An HttpConnection
     */
    public static HttpConnection createHttpConnection(Logger logger) {
        if (mPlatformComponent != null) {
            return mPlatformComponent.createHttpConnection(logger);
        } else {
            return createDefaultHttpConnection(logger);
        }
    }
    
    public static HttpConnection createDefaultHttpConnection(Logger logger) {
        return new JavaHttpConnection(logger, null, null, false);
    }

    public static HttpConnection createHttpsConnection(Logger logger, String clientCertificatePath, 
            char[] clientCertificatePassword, boolean ignoreSsl) {
        if (mPlatformComponent != null) {
            return mPlatformComponent.createHttpsConnection(logger, clientCertificatePath, 
                    clientCertificatePassword, ignoreSsl);
        } else {
            return createDefaultHttpsConnection(logger, clientCertificatePath, 
                    clientCertificatePassword, ignoreSsl);
        }
    }
    
    public static HttpConnection createDefaultHttpsConnection(Logger logger, String clientCertificatePath, 
            char[] clientCertificatePassword, boolean ignoreSsl) {
        return new JavaHttpConnection(logger, clientCertificatePath, clientCertificatePassword, ignoreSsl);
    }
    
    /**
     * Generates the User-Agent
     * @return String
     */
    public static String getUserAgent() {
        String osName;

        if (mPlatformComponent != null) {
            osName = mPlatformComponent.getOSName();
        } else {
            osName = System.getProperty("os.name").toLowerCase(Locale.getDefault());
        }
        String userAgent = String.format("SignalR (lang=Java; os=%s; version=2.0)", osName);

        return userAgent;
    }
}

package com.oneidentity.safeguard.safeguardjava;

import com.oneidentity.safeguard.safeguardjava.authentication.AccessTokenAuthenticator;
import com.oneidentity.safeguard.safeguardjava.authentication.AnonymousAuthenticator;
import com.oneidentity.safeguard.safeguardjava.authentication.CertificateAuthenticator;
import com.oneidentity.safeguard.safeguardjava.authentication.IAuthenticationMechanism;
import com.oneidentity.safeguard.safeguardjava.authentication.PasswordAuthenticator;
import com.oneidentity.safeguard.safeguardjava.event.ISafeguardEventListener;
import com.oneidentity.safeguard.safeguardjava.event.PersistentSafeguardA2AEventListener;
import com.oneidentity.safeguard.safeguardjava.event.PersistentSafeguardEventListener;
import com.oneidentity.safeguard.safeguardjava.exceptions.ObjectDisposedException;
import com.oneidentity.safeguard.safeguardjava.exceptions.SafeguardForJavaException;
import com.oneidentity.safeguard.safeguardjava.event.ISafeguardEventHandler;


/** 
* This static class provides static methods for connecting to Safeguard API.
*/
public final class Safeguard
{
    private static final int DEFAULTAPIVERSION = 2;
    
    private Safeguard() {
        
    }

    private static SafeguardConnection GetConnection(IAuthenticationMechanism authenticationMechanism) throws ObjectDisposedException, SafeguardForJavaException
    {
        authenticationMechanism.refreshAccessToken();
        return new SafeguardConnection(authenticationMechanism);
    }

    /**
     *  Connect to Safeguard API using an API access token.
     *
     *   @param networkAddress  Network address of Safeguard appliance.
     *   @param accessToken     Existing API access token.
     *   @param apiVersion      Target API version to use.
     *   @param ignoreSsl       Ignore server certificate validation.
     *   @return                Reusable Safeguard API connection.
     */ 
    public static ISafeguardConnection Connect(String networkAddress, char[] accessToken,
        Integer apiVersion, Boolean ignoreSsl)
    {
        int version = DEFAULTAPIVERSION;
        if (apiVersion != null)
            version = apiVersion;
        
        boolean sslIgnore = false;
        if (ignoreSsl != null)
            sslIgnore = ignoreSsl;
        
        // Don't try to refresh access token on the access token connect method because it cannot be refreshed
        // So, don't use GetConnection() function above
        return new SafeguardConnection(new AccessTokenAuthenticator(networkAddress, accessToken, version, sslIgnore));
    }

    /**
     *  Connect to Safeguard API using a user name and password.
     *
     *   @param networkAddress  Network address of Safeguard appliance.
     *   @param provider        Safeguard authentication provider name (e.g. local).
     *   @param username        User name to use for authentication.
     *   @param password        User password to use for authentication.
     *   @param apiVersion      Target API version to use.
     *   @param ignoreSsl       Ignore server certificate validation.
     *   @return                Reusable Safeguard API connection.
     *   @throws ObjectDisposedException Object has already been disposed.
     *   @throws SafeguardForJavaException General Safeguard for Java exception.
     */ 
    public static ISafeguardConnection Connect(String networkAddress, String provider, String username,
        char[] password, Integer apiVersion, Boolean ignoreSsl) throws ObjectDisposedException, SafeguardForJavaException
    {
        int version = DEFAULTAPIVERSION;
        if (apiVersion != null)
            version = apiVersion;
        
        boolean sslIgnore = false;
        if (ignoreSsl != null)
            sslIgnore = ignoreSsl;
        
        return GetConnection(new PasswordAuthenticator(networkAddress, provider, username, password, version,
            sslIgnore));
    }

    /**
     *  Connect to Safeguard API using a certificate from the keystore.  The appropriate keystore must
     *   have been loaded in the java process.
     *
     *   @param networkAddress          Network address of Safeguard appliance.
     *   @param keystorePath            Path to the keystore containing the client certificate.
     *   @param keystorePassword        Keystore password.
     *   @param certificateAlias        Alias identifying a client certificate in the keystore.
     *   @param apiVersion              Target API version to use.
     *   @param ignoreSsl               Ignore server certificate validation.
     *   @return                        Reusable Safeguard API connection.
     *   @throws ObjectDisposedException Object has already been disposed.
     *   @throws SafeguardForJavaException General Safeguard for Java exception.
     */ 
    public static ISafeguardConnection Connect(String networkAddress, String keystorePath, char[] keystorePassword, String certificateAlias,
        Integer apiVersion, Boolean ignoreSsl) throws ObjectDisposedException, SafeguardForJavaException
    {
        int version = DEFAULTAPIVERSION;
        if (apiVersion != null)
            version = apiVersion;
        
        boolean sslIgnore = false;
        if (ignoreSsl != null)
            sslIgnore = ignoreSsl;
        
        return GetConnection(new CertificateAuthenticator(networkAddress, keystorePath, keystorePassword, certificateAlias, version, sslIgnore));
    }

    /**
     *  Connect to Safeguard API using a certificate stored in a file.
     *
     *   @param networkAddress      Network address of Safeguard appliance.
     *   @param certificatePath     Path to PFX (or PKCS12) certificate file also containing private key.
     *   @param certificatePassword Password to decrypt the certificate file.
     *   @param apiVersion          Target API version to use.
     *   @param ignoreSsl           Ignore server certificate validation.
     *   @return                    Reusable Safeguard API connection.
     *   @throws ObjectDisposedException Object has already been disposed.
     *   @throws SafeguardForJavaException General Safeguard for Java exception.
     */ 
    public static ISafeguardConnection Connect(String networkAddress, String certificatePath,
        char[] certificatePassword, Integer apiVersion, Boolean ignoreSsl) throws ObjectDisposedException, SafeguardForJavaException
    {
        int version = DEFAULTAPIVERSION;
        if (apiVersion != null)
            version = apiVersion;
        
        boolean sslIgnore = false;
        if (ignoreSsl != null)
            sslIgnore = ignoreSsl;
        
        return GetConnection(new CertificateAuthenticator(networkAddress, certificatePath, certificatePassword,
            version, sslIgnore));
    }

    /**
     *  Connect to Safeguard API anonymously.
     *
     *   @param networkAddress  Network address.
     *   @param apiVersion      API version.
     *   @param ignoreSsl       If set to <code>true</code> ignore ssl.
     *   @return                The connect.
     */ 
    public static ISafeguardConnection Connect(String networkAddress, Integer apiVersion, Boolean ignoreSsl)
    {
        int version = DEFAULTAPIVERSION;
        if (apiVersion != null)
            version = apiVersion;
        
        boolean sslIgnore = false;
        if (ignoreSsl != null)
            sslIgnore = ignoreSsl;
        
        // Don't try to refresh access token on the anonymous connect method because it cannot be refreshed
        // So, don't use GetConnection() function above
        return new SafeguardConnection(new AnonymousAuthenticator(networkAddress, version, sslIgnore));
    }

    /**
     * This static class provides access to Safeguard Event functionality with persistent event listeners. Persistent
     * event listeners can handle longer term service outages to reconnect SignalR even after it times out. It is
     * recommended to use these interfaces when listening for Safeguard events from a long-running service.
     */ 
    public static class Event
    {
        /**
         * Get a persistent event listener using a username and password credential for authentication.
         * 
         * @param networkAddress    Network address of Safeguard appliance.
         * @param provider          Safeguard authentication provider name (e.g. local).
         * @param username          User name to use for authentication.
         * @param password          User password to use for authentication.
         * @param apiVersion        Target API version to use.
         * @param ignoreSsl         Ignore server certificate validation.
         * @return                  New persistent Safeguard event listener.
         * @throws ObjectDisposedException Object has already been disposed.
         * @throws SafeguardForJavaException General Safeguard for Java exception.
         */ 
        public static ISafeguardEventListener GetPersistentEventListener(String networkAddress, String provider,
            String username, char[] password, Integer apiVersion, Boolean ignoreSsl) 
                throws ObjectDisposedException, SafeguardForJavaException
        {
            int version = DEFAULTAPIVERSION;
            if (apiVersion != null)
                version = apiVersion;
            
            boolean sslIgnore = false;
            if (ignoreSsl != null)
                sslIgnore = ignoreSsl;
            
            return new PersistentSafeguardEventListener(GetConnection(
                new PasswordAuthenticator(networkAddress, provider, username, password, version, ignoreSsl)));
        }

        /**
         * Get a persistent event listener using a client certificate stored in a file.
         * 
         * @param networkAddress        Network address of Safeguard appliance.
         * @param certificatePath       Path to PFX (or PKCS12) certificate file also containing private key.
         * @param certificatePassword   Password to decrypt the certificate file.
         * @param apiVersion            Target API version to use.
         * @param ignoreSsl             Ignore server certificate validation.
         * @return                      New persistent Safeguard event listener.
         * @throws ObjectDisposedException Object has already been disposed.
         * @throws SafeguardForJavaException General Safeguard for Java exception.
         */ 
        public static ISafeguardEventListener GetPersistentEventListener(String networkAddress, String certificatePath,
                char[] certificatePassword, Integer apiVersion, Boolean ignoreSsl) 
                throws ObjectDisposedException, SafeguardForJavaException
        {
            int version = DEFAULTAPIVERSION;
            if (apiVersion != null)
                version = apiVersion;
            
            boolean sslIgnore = false;
            if (ignoreSsl != null)
                sslIgnore = ignoreSsl;

            return new PersistentSafeguardEventListener(GetConnection(
                new CertificateAuthenticator(networkAddress, certificatePath, certificatePassword, version, ignoreSsl)));
        }

        /**
         * Get a persistent event listener using a client certificate from the certificate keystore for authentication.
         * 
         * @param networkAddress        Network address of Safeguard appliance.
         * @param keystorePath          Path to the keystore containing the client certificate.
         * @param keystorePassword      Keystore password.
         * @param certificateAlias      Alias identifying a client certificate in the keystore.
         * @param apiVersion            Target API version to use.
         * @param ignoreSsl             Ignore server certificate validation.
         * @return                      New persistent Safeguard event listener.
         * @throws ObjectDisposedException Object has already been disposed.
         * @throws SafeguardForJavaException General Safeguard for Java exception.
         */ 
        public static ISafeguardEventListener GetPersistentEventListener(String networkAddress,
            String keystorePath, char[] keystorePassword, String certificateAlias, Integer apiVersion, Boolean ignoreSsl) 
                throws ObjectDisposedException, SafeguardForJavaException
        {
            int version = DEFAULTAPIVERSION;
            if (apiVersion != null)
                version = apiVersion;
            
            boolean sslIgnore = false;
            if (ignoreSsl != null)
                sslIgnore = ignoreSsl;

            return new PersistentSafeguardEventListener(GetConnection(new CertificateAuthenticator(networkAddress,
                keystorePath, keystorePassword, certificateAlias, version, ignoreSsl)));
        }
    }
    
    /**
     *  This static class provides access to Safeguard A2A functionality.
     *
     */ 
    public static class A2A
    {
        /**
         *  Establish a Safeguard A2A context using a certificate from the keystore.  
         *
         *   @param networkAddress          Network address of Safeguard appliance.
         *   @param keystorePath            Path to the keystore containing the client certificate.
         *   @param keystorePassword        Keystore password.
         *   @param certificateAlias        Alias identifying a client certificate in the keystore.
         *   @param apiVersion              Target API version to use.
         *   @param ignoreSsl               Ignore server certificate validation.
         *   @return                        Reusable Safeguard A2A context.
         */
        public static ISafeguardA2AContext GetContext(String networkAddress, String keystorePath, char[] keystorePassword, String certificateAlias,
            Integer apiVersion, Boolean ignoreSsl)
        {
            int version = DEFAULTAPIVERSION;
            if (apiVersion != null)
                version = apiVersion;

            boolean sslIgnore = false;
            if (ignoreSsl != null)
                sslIgnore = ignoreSsl;
        
            return new SafeguardA2AContext(networkAddress, certificateAlias, keystorePath, keystorePassword, version, sslIgnore);
        }

        /**
         *  Establish a Safeguard A2A context using a certificate stored in a file.
         *
         *   @param networkAddress      Network address of Safeguard appliance.
         *   @param certificatePath     Path to PFX (or PKCS12) certificate file also containing private key.
         *   @param certificatePassword Password to decrypt the certificate file.
         *   @param apiVersion          Target API version to use.
         *   @param ignoreSsl           Ignore server certificate validation.
         *   @return                    Reusable Safeguard A2A context.
         */ 
        public static ISafeguardA2AContext GetContext(String networkAddress, String certificatePath,
            char[] certificatePassword, Integer apiVersion, Boolean ignoreSsl)
        {
            int version = DEFAULTAPIVERSION;
            if (apiVersion != null)
                version = apiVersion;

            boolean sslIgnore = false;
            if (ignoreSsl != null)
                sslIgnore = ignoreSsl;
            
            return new SafeguardA2AContext(networkAddress, certificatePath, certificatePassword, version, sslIgnore);
        }
        
        /**
         * This static class provides access to Safeguard A2A Event functionality with persistent event listeners. Persistent
         * event listeners can handle longer term service outages to reconnect SignalR even after it times out. It is
         * recommended to use these interfaces when listening for Safeguard events from a long-running service.
         */ 
        public static class Event
        {
            /**
             * Get a persistent A2A event listener for Gets an A2A event listener. The handler passed in will be registered
             * for the AssetAccountPasswordUpdated event, which is the only one supported in A2A.
             * 
             * @param apiKey            API key corresponding to the configured account to listen for.
             * @param handler           A delegate to call any time the AssetAccountPasswordUpdate event occurs.
             * @param networkAddress    Network address of Safeguard appliance.
             * @param keystorePath      Path to the keystore containing the client certificate.
             * @param keystorePassword  Keystore password.
             * @param certificateAlias  Alias identifying a client certificate in the keystore.
             * @param apiVersion        Target API version to use.
             * @param ignoreSsl         Ignore server certificate validation.
             * @return                  New persistent A2A event listener.
             * @throws ObjectDisposedException Object has already been disposed.
             */
            public static ISafeguardEventListener GetPersistentA2AEventListener(char[] apiKey, ISafeguardEventHandler handler, 
                    String networkAddress, String keystorePath, char[] keystorePassword, String certificateAlias,
                    Integer apiVersion, Boolean ignoreSsl) 
                    throws ObjectDisposedException
            {
            int version = DEFAULTAPIVERSION;
            if (apiVersion != null)
                version = apiVersion;

            boolean sslIgnore = false;
            if (ignoreSsl != null)
                sslIgnore = ignoreSsl;
            
            return new PersistentSafeguardA2AEventListener(
                    new SafeguardA2AContext(networkAddress, certificateAlias, keystorePath, keystorePassword, version, ignoreSsl), 
                    apiKey, handler);
            }

            /**
             * Get a persistent A2A event listener for Gets an A2A event listener. The handler passed in will be registered
             * for the AssetAccountPasswordUpdated event, which is the only one supported in A2A.
             * 
             * @param apiKey                API key corresponding to the configured account to listen for.
             * @param handler               A delegate to call any time the AssetAccountPasswordUpdate event occurs.
             * @param networkAddress        Network address of Safeguard appliance.
             * @param certificatePath       Path to PFX (or PKCS12) certificate file also containing private key.
             * @param certificatePassword   Password to decrypt the certificate file.
             * @param apiVersion            Target API version to use.
             * @param ignoreSsl             Ignore server certificate validation.
             * @return                      New persistent A2A event listener.
             * @throws ObjectDisposedException Object has already been disposed.
             */
            public static ISafeguardEventListener GetPersistentA2AEventListener(char[] apiKey,
                    ISafeguardEventHandler handler, String networkAddress, String certificatePath,
                    char[] certificatePassword, Integer apiVersion, Boolean ignoreSsl) 
                    throws ObjectDisposedException
            {
            int version = DEFAULTAPIVERSION;
            if (apiVersion != null)
                version = apiVersion;

            boolean sslIgnore = false;
            if (ignoreSsl != null)
                sslIgnore = ignoreSsl;
            
            return new PersistentSafeguardA2AEventListener(
                    new SafeguardA2AContext(networkAddress, certificatePath, certificatePassword, version,
                        ignoreSsl), apiKey, handler);
            }
        }
    }
}

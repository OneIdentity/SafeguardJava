package com.oneidentity.safeguard.safeguardjava;

import com.oneidentity.safeguard.safeguardjava.authentication.AccessTokenAuthenticator;
import com.oneidentity.safeguard.safeguardjava.authentication.AnonymousAuthenticator;
import com.oneidentity.safeguard.safeguardjava.authentication.CertificateAuthenticator;
import com.oneidentity.safeguard.safeguardjava.authentication.IAuthenticationMechanism;
import com.oneidentity.safeguard.safeguardjava.authentication.PasswordAuthenticator;
import com.oneidentity.safeguard.safeguardjava.exceptions.ObjectDisposedException;
import com.oneidentity.safeguard.safeguardjava.exceptions.SafeguardForJavaException;


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
     *   @param certificateThumbprint   SHA-1 hash identifying a client certificate in personal (My) store.
     *   @param apiVersion              Target API version to use.
     *   @param ignoreSsl               Ignore server certificate validation.
     *   @return                        Reusable Safeguard API connection.
     *   @throws ObjectDisposedException Object has already been disposed.
     *   @throws SafeguardForJavaException General Safeguard for Java exception.
     */ 
    public static ISafeguardConnection Connect(String networkAddress, String certificateThumbprint,
        Integer apiVersion, Boolean ignoreSsl) throws ObjectDisposedException, SafeguardForJavaException
    {
        int version = DEFAULTAPIVERSION;
        if (apiVersion != null)
            version = apiVersion;
        
        boolean sslIgnore = false;
        if (ignoreSsl != null)
            sslIgnore = ignoreSsl;
        
        return GetConnection(new CertificateAuthenticator(networkAddress, certificateThumbprint, version, sslIgnore));
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
     *  This static class provides access to Safeguard A2A functionality.
     *
     */ 
    public static class A2A
    {
        /**
         *  Establish a Safeguard A2A context using a certificate from the keystore.  The appropriate keystore must
         *   have been loaded in the java process.
         *
         *   @param networkAddress          Network address of Safeguard appliance.
         *   @param certificateThumbprint   SHA-1 hash identifying a client certificate in personal (My) store.
         *   @param apiVersion              Target API version to use.
         *   @param ignoreSsl               Ignore server certificate validation.
         *   @return                        Reusable Safeguard A2A context.
         */
        public static ISafeguardA2AContext GetContext(String networkAddress, String certificateThumbprint,
            Integer apiVersion, Boolean ignoreSsl)
        {
            int version = DEFAULTAPIVERSION;
            if (apiVersion != null)
                version = apiVersion;

            boolean sslIgnore = false;
            if (ignoreSsl != null)
                sslIgnore = ignoreSsl;
        
            return new SafeguardA2AContext(networkAddress, certificateThumbprint, version, sslIgnore);
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
    }
}

package com.oneidentity.safeguard.safeguardclient;

import com.oneidentity.safeguard.safeguardclient.authentication.AccessTokenAuthenticator;
import com.oneidentity.safeguard.safeguardclient.authentication.AnonymousAuthenticator;
import com.oneidentity.safeguard.safeguardclient.authentication.CertificateAuthenticator;
import com.oneidentity.safeguard.safeguardclient.authentication.IAuthenticationMechanism;
import com.oneidentity.safeguard.safeguardclient.authentication.PasswordAuthenticator;
import com.oneidentity.safeguard.safeguardclient.exceptions.ObjectDisposedException;
import com.oneidentity.safeguard.safeguardclient.exceptions.SafeguardForJavaException;


/// <summary>
/// This static class provides static methods for connecting to Safeguard API.
/// </summary>
public final class Safeguard
{
    private static final int DEFAULTAPIVERSION = 2;
    
    private Safeguard() {
        
    }

    private static SafeguardConnection GetConnection(IAuthenticationMechanism authenticationMechanism) throws ObjectDisposedException, SafeguardForJavaException
    {
        authenticationMechanism.RefreshAccessToken();
        return new SafeguardConnection(authenticationMechanism);
    }

    /// <summary>
    /// Connect to Safeguard API using an API access token.
    /// </summary>
    /// <param name="networkAddress">Network address of Safeguard appliance.</param>
    /// <param name="accessToken">Existing API access token.</param>
    /// <param name="apiVersion">Target API version to use.</param>
    /// <param name="ignoreSsl">Ignore server certificate validation.</param>
    /// <returns>Reusable Safeguard API connection.</returns>
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

    /// <summary>
    /// Connect to Safeguard API using a user name and password.
    /// </summary>
    /// <param name="networkAddress">Network address of Safeguard appliance.</param>
    /// <param name="provider">Safeguard authentication provider name (e.g. local).</param>
    /// <param name="username">User name to use for authentication.</param>
    /// <param name="password">User password to use for authentication.</param>
    /// <param name="apiVersion">Target API version to use.</param>
    /// <param name="ignoreSsl">Ignore server certificate validation.</param>
    /// <returns>Reusable Safeguard API connection.</returns>
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

    /// <summary>
    /// Connect to Safeguard API using a certificate from the certificate store.  Use PowerShell to list certificates with
    /// SHA-1 thumbprint.  PS> gci Cert:\CurrentUser\My
    /// </summary>
    /// <param name="networkAddress">Network address of Safeguard appliance.</param>
    /// <param name="certificateThumbprint">SHA-1 hash identifying a client certificate in personal (My) store.</param>
    /// <param name="apiVersion">Target API version to use.</param>
    /// <param name="ignoreSsl">Ignore server certificate validation.</param>
    /// <returns>Reusable Safeguard API connection.</returns>
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

    /// <summary>
    /// Connect to Safeguard API using a certificate stored in a file.
    /// </summary>
    /// <param name="networkAddress">Network address of Safeguard appliance.</param>
    /// <param name="certificatePath">Path to PFX (or PKCS12) certificate file also containing private key.</param>
    /// <param name="certificatePassword">Password to decrypt the certificate file.</param>
    /// <param name="apiVersion">Target API version to use.</param>
    /// <param name="ignoreSsl">Ignore server certificate validation.</param>
    /// <returns>Reusable Safeguard API connection.</returns>
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

    /// <summary>
    /// Connect to Safeguard API anonymously.
    /// </summary>
    /// <returns>The connect.</returns>
    /// <param name="networkAddress">Network address.</param>
    /// <param name="apiVersion">API version.</param>
    /// <param name="ignoreSsl">If set to <c>true</c> ignore ssl.</param>
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

    /// <summary>
    /// This static class provides access to Safeguard A2A functionality.
    /// </summary>
    public static class A2A
    {
        /// <summary>
        /// Establish a Safeguard A2A context using a certificate from the certificate store.  Use PowerShell to
        /// list certificates with SHA-1 thumbprint.  PS> gci Cert:\CurrentUser\My
        /// </summary>
        /// <param name="networkAddress">Network address of Safeguard appliance.</param>
        /// <param name="certificateThumbprint">SHA-1 hash identifying a client certificate in personal (My) store.</param>
        /// <param name="apiVersion">Target API version to use.</param>
        /// <param name="ignoreSsl">Ignore server certificate validation.</param>
        /// <returns>Reusable Safeguard A2A context.</returns>
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

        /// <summary>
        /// Establish a Safeguard A2A context using a certificate stored in a file.
        /// </summary>
        /// <param name="networkAddress">Network address of Safeguard appliance.</param>
        /// <param name="certificatePath">Path to PFX (or PKCS12) certificate file also containing private key.</param>
        /// <param name="certificatePassword">Password to decrypt the certificate file.</param>
        /// <param name="apiVersion">Target API version to use.</param>
        /// <param name="ignoreSsl">Ignore server certificate validation.</param>
        /// <returns>Reusable Safeguard A2A context.</returns>
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

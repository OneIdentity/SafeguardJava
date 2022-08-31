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
import com.oneidentity.safeguard.safeguardjava.exceptions.ArgumentException;
import java.util.List;
import javax.net.ssl.HostnameVerifier;

/**
 * This static class provides static methods for connecting to Safeguard API.
 */
public final class Safeguard {

    private static final int DEFAULTAPIVERSION = 4;

    private Safeguard() {

    }

    private static SafeguardConnection getConnection(IAuthenticationMechanism authenticationMechanism) throws ObjectDisposedException, SafeguardForJavaException {
        authenticationMechanism.refreshAccessToken();
        return new SafeguardConnection(authenticationMechanism);
    }

    /**
     *  Connect to Safeguard API using an API access token.
     *
     *  @param networkAddress Network address of Safeguard appliance.
     *  @param accessToken Existing API access token.
     *  @param apiVersion Target API version to use.
     *  @param ignoreSsl Ignore server certificate validation.
     * 
     *  @return Reusable Safeguard API connection.
     *  @throws ArgumentException Invalid argument.
     */
    public static ISafeguardConnection connect(String networkAddress, char[] accessToken,
            Integer apiVersion, Boolean ignoreSsl) throws ArgumentException {
        int version = DEFAULTAPIVERSION;
        if (apiVersion != null) {
            version = apiVersion;
        }

        boolean sslIgnore = false;
        if (ignoreSsl != null) {
            sslIgnore = ignoreSsl;
        }

        // Don't try to refresh access token on the access token connect method because it cannot be refreshed
        // So, don't use GetConnection() function above
        return new SafeguardConnection(new AccessTokenAuthenticator(networkAddress, accessToken, version, sslIgnore, null));
    }

    /**
     *  Connect to Safeguard API using an API access token.
     *
     *  @param networkAddress Network address of Safeguard appliance.
     *  @param accessToken Existing API access token.
     *  @param apiVersion Target API version to use.
     *  @param validationCallback Callback function to be executed during SSL certificate validation.
     * 
     *  @return Reusable Safeguard API connection.
     *  @throws ArgumentException Invalid argument.
     */
    public static ISafeguardConnection connect(String networkAddress, char[] accessToken,
            HostnameVerifier validationCallback, Integer apiVersion) throws ArgumentException {
        int version = DEFAULTAPIVERSION;
        if (apiVersion != null) {
            version = apiVersion;
        }

        // Don't try to refresh access token on the access token connect method because it cannot be refreshed
        // So, don't use GetConnection() function above
        return new SafeguardConnection(new AccessTokenAuthenticator(networkAddress, accessToken, version, false, validationCallback));
    }
    
    /**
     *  Connect to Safeguard API using a user name and password.
     *
     *  @param networkAddress Network address of Safeguard appliance.
     *  @param provider Safeguard authentication provider name (e.g. local).
     *  @param username User name to use for authentication.
     *  @param password User password to use for authentication.
     *  @param apiVersion Target API version to use.
     *  @param ignoreSsl Ignore server certificate validation.
     *  @return Reusable Safeguard API connection.
     *  @throws ObjectDisposedException Object has already been disposed.
     *  @throws ArgumentException Invalid argument.
     *  @throws SafeguardForJavaException General Safeguard for Java exception.
     */
    public static ISafeguardConnection connect(String networkAddress, String provider, String username,
            char[] password, Integer apiVersion, Boolean ignoreSsl) 
            throws ObjectDisposedException, ArgumentException, SafeguardForJavaException {
        int version = DEFAULTAPIVERSION;
        if (apiVersion != null) {
            version = apiVersion;
        }

        boolean sslIgnore = false;
        if (ignoreSsl != null) {
            sslIgnore = ignoreSsl;
        }

        return getConnection(new PasswordAuthenticator(networkAddress, provider, username, password, version,
                sslIgnore, null));
    }

    /**
     *  Connect to Safeguard API using a user name and password.
     *
     *  @param networkAddress Network address of Safeguard appliance.
     *  @param provider Safeguard authentication provider name (e.g. local).
     *  @param username User name to use for authentication.
     *  @param password User password to use for authentication.
     *  @param apiVersion Target API version to use.
     *  @param validationCallback Callback function to be executed during SSL certificate validation.
     *  @return Reusable Safeguard API connection.
     *  @throws ObjectDisposedException Object has already been disposed.
     *  @throws ArgumentException Invalid argument.
     *  @throws SafeguardForJavaException General Safeguard for Java exception.
     */
    public static ISafeguardConnection connect(String networkAddress, String provider, String username,
            char[] password, HostnameVerifier validationCallback, Integer apiVersion) 
            throws ObjectDisposedException, ArgumentException, SafeguardForJavaException {
        int version = DEFAULTAPIVERSION;
        if (apiVersion != null) {
            version = apiVersion;
        }

        return getConnection(new PasswordAuthenticator(networkAddress, provider, username, password, version,
                false, validationCallback));
    }

    /**
     *  Connect to Safeguard API using a certificate from the keystore. The
     *  appropriate keystore must have been loaded in the java process.
     *
     *  @param networkAddress Network address of Safeguard appliance.
     *  @param keystorePath Path to the keystore containing the client certificate.
     *  @param keystorePassword Keystore password.
     *  @param certificateAlias Alias identifying a client certificate in the keystore.
     *  @param apiVersion Target API version to use.
     *  @param ignoreSsl Ignore server certificate validation.
     * 
     *  @return Reusable Safeguard API connection.
     *  @throws ObjectDisposedException Object has already been disposed.
     *  @throws SafeguardForJavaException General Safeguard for Java exception.
     */
    public static ISafeguardConnection connect(String networkAddress, String keystorePath, 
            char[] keystorePassword, String certificateAlias,
            Integer apiVersion, Boolean ignoreSsl) 
            throws ObjectDisposedException, SafeguardForJavaException {
        int version = DEFAULTAPIVERSION;
        if (apiVersion != null) {
            version = apiVersion;
        }

        boolean sslIgnore = false;
        if (ignoreSsl != null) {
            sslIgnore = ignoreSsl;
        }

        return getConnection(new CertificateAuthenticator(networkAddress, keystorePath, 
                keystorePassword, certificateAlias, version, sslIgnore, null));
    }

    /**
     *  Connect to Safeguard API using a certificate from the keystore. The
     *  appropriate keystore must have been loaded in the java process.
     *
     *  @param networkAddress Network address of Safeguard appliance.
     *  @param keystorePath Path to the keystore containing the client certificate.
     *  @param keystorePassword Keystore password.
     *  @param certificateAlias Alias identifying a client certificate in the keystore.
     *  @param apiVersion Target API version to use.
     *  @param validationCallback Callback function to be executed during SSL certificate validation.
     * 
     *  @return Reusable Safeguard API connection.
     *  @throws ObjectDisposedException Object has already been disposed.
     *  @throws SafeguardForJavaException General Safeguard for Java exception.
     */
    public static ISafeguardConnection connect(String networkAddress, String keystorePath, 
            char[] keystorePassword, String certificateAlias,
            HostnameVerifier validationCallback, Integer apiVersion) 
            throws ObjectDisposedException, SafeguardForJavaException {
        int version = DEFAULTAPIVERSION;
        if (apiVersion != null) {
            version = apiVersion;
        }

        return getConnection(new CertificateAuthenticator(networkAddress, keystorePath, 
                keystorePassword, certificateAlias, version, false, validationCallback));
    }

    /**
     *  Connect to Safeguard API using a certificate from the Windows 
     *  certificate store. This is a Windows only API and requires that the
     *  SunMSCAPI security provider is available in the Java environment.
     *
     *  @param networkAddress Network address of Safeguard appliance.
     *  @param thumbprint Thumbprint of the client certificate.
     *  @param apiVersion Target API version to use.
     *  @param ignoreSsl Ignore server certificate validation.
     * 
     *  @return Reusable Safeguard API connection.
     *  @throws ObjectDisposedException Object has already been disposed.
     *  @throws SafeguardForJavaException General Safeguard for Java exception.
     */
    public static ISafeguardConnection connect(String networkAddress, String thumbprint, 
            Integer apiVersion, Boolean ignoreSsl) 
            throws ObjectDisposedException, SafeguardForJavaException {
        int version = DEFAULTAPIVERSION;
        if (apiVersion != null) {
            version = apiVersion;
        }

        boolean sslIgnore = false;
        if (ignoreSsl != null) {
            sslIgnore = ignoreSsl;
        }

        if (Utils.isWindows()) {
            if (!Utils.isSunMSCAPILoaded()) {
                throw new SafeguardForJavaException("Missing SunMSCAPI provider. The SunMSCAPI provider must be added as a security provider in $JAVA_HOME/jre/lib/security/java.security configuration file.");
            }
        }
        else {
            throw new SafeguardForJavaException("Not implemented. This function is only available on the Windows platform.");
        }
        
        return getConnection(new CertificateAuthenticator(networkAddress, thumbprint, 
                version, sslIgnore, null));
    }

    /**
     *  Connect to Safeguard API using a certificate from the Windows 
     *  certificate store. This is a Windows only API and requires that the
     *  SunMSCAPI security provider is available in the Java environment.
     *
     *  @param networkAddress Network address of Safeguard appliance.
     *  @param thumbprint Thumbprint of the client certificate.
     *  @param apiVersion Target API version to use.
     *  @param validationCallback Callback function to be executed during SSL certificate validation.
     * 
     *  @return Reusable Safeguard API connection.
     *  @throws ObjectDisposedException Object has already been disposed.
     *  @throws SafeguardForJavaException General Safeguard for Java exception.
     */
    public static ISafeguardConnection connect(String networkAddress, String thumbprint, 
            HostnameVerifier validationCallback, Integer apiVersion) 
            throws ObjectDisposedException, SafeguardForJavaException {
        int version = DEFAULTAPIVERSION;
        if (apiVersion != null) {
            version = apiVersion;
        }

        if (Utils.isWindows()) {
            if (!Utils.isSunMSCAPILoaded()) {
                throw new SafeguardForJavaException("Missing SunMSCAPI provider. The SunMSCAPI provider must be added as a security provider in $JAVA_HOME/jre/lib/security/java.security configuration file.");
            }
        }
        else {
            throw new SafeguardForJavaException("Not implemented. This function is only available on the Windows platform.");
        }
        
        return getConnection(new CertificateAuthenticator(networkAddress, thumbprint, 
                version, false, validationCallback));
    }

    /**
     *  Connect to Safeguard API using a certificate stored in a file.
     *
     *  @param networkAddress Network address of Safeguard appliance.
     *  @param certificatePath Path to PFX (or PKCS12) certificate file also
     *  containing private key.
     *  @param certificatePassword Password to decrypt the certificate file.
     *  @param apiVersion Target API version to use.
     *  @param ignoreSsl Ignore server certificate validation.
     * 
     *  @return Reusable Safeguard API connection.
     *  @throws ObjectDisposedException Object has already been disposed.
     *  @throws SafeguardForJavaException General Safeguard for Java exception.
     */
    public static ISafeguardConnection connect(String networkAddress, String certificatePath,
            char[] certificatePassword, Integer apiVersion, Boolean ignoreSsl) 
            throws ObjectDisposedException, SafeguardForJavaException {
        int version = DEFAULTAPIVERSION;
        if (apiVersion != null) {
            version = apiVersion;
        }

        boolean sslIgnore = false;
        if (ignoreSsl != null) {
            sslIgnore = ignoreSsl;
        }

        return getConnection(new CertificateAuthenticator(networkAddress, certificatePath, certificatePassword,
                version, sslIgnore, null));
    }

    /**
     *  Connect to Safeguard API using a certificate stored in a file.
     *
     *  @param networkAddress Network address of Safeguard appliance.
     *  @param certificatePath Path to PFX (or PKCS12) certificate file also
     *  containing private key.
     *  @param certificatePassword Password to decrypt the certificate file.
     *  @param apiVersion Target API version to use.
     *  @param validationCallback Callback function to be executed during SSL certificate validation.
     * 
     *  @return Reusable Safeguard API connection.
     *  @throws ObjectDisposedException Object has already been disposed.
     *  @throws SafeguardForJavaException General Safeguard for Java exception.
     */
    public static ISafeguardConnection connect(String networkAddress, String certificatePath,
            char[] certificatePassword, HostnameVerifier validationCallback, Integer apiVersion) 
            throws ObjectDisposedException, SafeguardForJavaException {
        int version = DEFAULTAPIVERSION;
        if (apiVersion != null) {
            version = apiVersion;
        }

        return getConnection(new CertificateAuthenticator(networkAddress, certificatePath, certificatePassword,
                version, false, validationCallback));
    }

    /**
     *  Connect to Safeguard API using a certificate stored in memory.
     *
     *  @param networkAddress Network address of Safeguard appliance.
     *  @param certificateData Bytes containing a PFX (or PKCS12) formatted certificate and private key.
     *  @param certificatePassword Password to decrypt the certificate data.
     *  @param certificateAlias Alias identifying a client certificate in the keystore.
     *  @param apiVersion Target API version to use.
     *  @param ignoreSsl Ignore server certificate validation.
     * 
     *  @return Reusable Safeguard API connection.
     *  @throws ObjectDisposedException Object has already been disposed.
     *  @throws SafeguardForJavaException General Safeguard for Java exception.
     */
    public static ISafeguardConnection connect(String networkAddress, byte[] certificateData,
            char[] certificatePassword, String certificateAlias, Integer apiVersion, Boolean ignoreSsl) 
            throws ObjectDisposedException, SafeguardForJavaException {
        int version = DEFAULTAPIVERSION;
        if (apiVersion != null) {
            version = apiVersion;
        }

        boolean sslIgnore = false;
        if (ignoreSsl != null) {
            sslIgnore = ignoreSsl;
        }

        return getConnection(new CertificateAuthenticator(networkAddress, certificateData, certificatePassword, certificateAlias,
                version, sslIgnore, null));
    }
    
    /**
     *  Connect to Safeguard API using a certificate stored in memory.
     *
     *  @param networkAddress Network address of Safeguard appliance.
     *  @param certificateData Bytes containing a PFX (or PKCS12) formatted certificate and private key.
     *  @param certificatePassword Password to decrypt the certificate data.
     *  @param certificateAlias Alias identifying a client certificate in the keystore.
     *  @param apiVersion Target API version to use.
     *  @param validationCallback Callback function to be executed during SSL certificate validation.
     * 
     *  @return Reusable Safeguard API connection.
     *  @throws ObjectDisposedException Object has already been disposed.
     *  @throws SafeguardForJavaException General Safeguard for Java exception.
     */
    public static ISafeguardConnection connect(String networkAddress, byte[] certificateData,
            char[] certificatePassword, String certificateAlias, HostnameVerifier validationCallback, Integer apiVersion) 
            throws ObjectDisposedException, SafeguardForJavaException {
        int version = DEFAULTAPIVERSION;
        if (apiVersion != null) {
            version = apiVersion;
        }

        return getConnection(new CertificateAuthenticator(networkAddress, certificateData, certificatePassword, certificateAlias,
                version, false, validationCallback));
    }
    
    /**
     *  Connect to Safeguard API using a certificate from the keystore. The
     *  appropriate keystore must have been loaded in the java process.
     *
     *  @param networkAddress Network address of Safeguard appliance.
     *  @param keystorePath Path to the keystore containing the client certificate.
     *  @param keystorePassword Keystore password.
     *  @param certificateAlias Alias identifying a client certificate in the keystore.
     *  @param provider Safeguard authentication provider name (e.g. local).
     *  @param apiVersion Target API version to use.
     *  @param ignoreSsl Ignore server certificate validation.
     * 
     *  @return Reusable Safeguard API connection.
     *  @throws ObjectDisposedException Object has already been disposed.
     *  @throws SafeguardForJavaException General Safeguard for Java exception.
     */
    public static ISafeguardConnection connect(String networkAddress, String keystorePath, 
            char[] keystorePassword, String certificateAlias, String provider,
            Integer apiVersion, Boolean ignoreSsl) 
            throws ObjectDisposedException, SafeguardForJavaException {
        int version = DEFAULTAPIVERSION;
        if (apiVersion != null) {
            version = apiVersion;
        }

        boolean sslIgnore = false;
        if (ignoreSsl != null) {
            sslIgnore = ignoreSsl;
        }

        return getConnection(new CertificateAuthenticator(networkAddress, keystorePath, 
                keystorePassword, certificateAlias, version, sslIgnore, null, provider));
    }

    /**
     *  Connect to Safeguard API using a certificate from the keystore. The
     *  appropriate keystore must have been loaded in the java process.
     *
     *  @param networkAddress Network address of Safeguard appliance.
     *  @param keystorePath Path to the keystore containing the client certificate.
     *  @param keystorePassword Keystore password.
     *  @param certificateAlias Alias identifying a client certificate in the keystore.
     *  @param provider Safeguard authentication provider name (e.g. local).
     *  @param apiVersion Target API version to use.
     *  @param validationCallback Callback function to be executed during SSL certificate validation.
     * 
     *  @return Reusable Safeguard API connection.
     *  @throws ObjectDisposedException Object has already been disposed.
     *  @throws SafeguardForJavaException General Safeguard for Java exception.
     */
    public static ISafeguardConnection connect(String networkAddress, String keystorePath, 
            char[] keystorePassword, String certificateAlias,
            HostnameVerifier validationCallback,  String provider, Integer apiVersion) 
            throws ObjectDisposedException, SafeguardForJavaException {
        int version = DEFAULTAPIVERSION;
        if (apiVersion != null) {
            version = apiVersion;
        }

        return getConnection(new CertificateAuthenticator(networkAddress, keystorePath, 
                keystorePassword, certificateAlias, version, false, validationCallback, provider));
    }

    /**
     *  Connect to Safeguard API using a certificate from the Windows 
     *  certificate store. This is a Windows only API and requires that the
     *  SunMSCAPI security provider is available in the Java environment.
     *
     *  @param networkAddress Network address of Safeguard appliance.
     *  @param thumbprint Thumbprint of the client certificate.
     *  @param provider Safeguard authentication provider name (e.g. local).
     *  @param apiVersion Target API version to use.
     *  @param ignoreSsl Ignore server certificate validation.
     * 
     *  @return Reusable Safeguard API connection.
     *  @throws ObjectDisposedException Object has already been disposed.
     *  @throws SafeguardForJavaException General Safeguard for Java exception.
     */
    public static ISafeguardConnection connect(String networkAddress, String thumbprint, 
             String provider, Integer apiVersion, Boolean ignoreSsl) 
            throws ObjectDisposedException, SafeguardForJavaException {
        int version = DEFAULTAPIVERSION;
        if (apiVersion != null) {
            version = apiVersion;
        }

        boolean sslIgnore = false;
        if (ignoreSsl != null) {
            sslIgnore = ignoreSsl;
        }

        if (Utils.isWindows()) {
            if (!Utils.isSunMSCAPILoaded()) {
                throw new SafeguardForJavaException("Missing SunMSCAPI provider. The SunMSCAPI provider must be added as a security provider in $JAVA_HOME/jre/lib/security/java.security configuration file.");
            }
        }
        else {
            throw new SafeguardForJavaException("Not implemented. This function is only available on the Windows platform.");
        }
        
        return getConnection(new CertificateAuthenticator(networkAddress, thumbprint, 
                version, sslIgnore, null, provider));
    }

    /**
     *  Connect to Safeguard API using a certificate from the Windows 
     *  certificate store. This is a Windows only API and requires that the
     *  SunMSCAPI security provider is available in the Java environment.
     *
     *  @param networkAddress Network address of Safeguard appliance.
     *  @param thumbprint Thumbprint of the client certificate.
     *  @param provider Safeguard authentication provider name (e.g. local).
     *  @param apiVersion Target API version to use.
     *  @param validationCallback Callback function to be executed during SSL certificate validation.
     * 
     *  @return Reusable Safeguard API connection.
     *  @throws ObjectDisposedException Object has already been disposed.
     *  @throws SafeguardForJavaException General Safeguard for Java exception.
     */
    public static ISafeguardConnection connect(String networkAddress, String thumbprint, 
            HostnameVerifier validationCallback,  String provider, Integer apiVersion) 
            throws ObjectDisposedException, SafeguardForJavaException {
        int version = DEFAULTAPIVERSION;
        if (apiVersion != null) {
            version = apiVersion;
        }

        if (Utils.isWindows()) {
            if (!Utils.isSunMSCAPILoaded()) {
                throw new SafeguardForJavaException("Missing SunMSCAPI provider. The SunMSCAPI provider must be added as a security provider in $JAVA_HOME/jre/lib/security/java.security configuration file.");
            }
        }
        else {
            throw new SafeguardForJavaException("Not implemented. This function is only available on the Windows platform.");
        }
        
        return getConnection(new CertificateAuthenticator(networkAddress, thumbprint, 
                version, false, validationCallback, provider));
    }

    /**
     *  Connect to Safeguard API using a certificate stored in a file.
     *
     *  @param networkAddress Network address of Safeguard appliance.
     *  @param certificatePath Path to PFX (or PKCS12) certificate file also
     *  containing private key.
     *  @param certificatePassword Password to decrypt the certificate file.
     *  @param apiVersion Target API version to use.
     *  @param ignoreSsl Ignore server certificate validation.
     *  @param provider Safeguard authentication provider name (e.g. local).
     * 
     *  @return Reusable Safeguard API connection.
     *  @throws ObjectDisposedException Object has already been disposed.
     *  @throws SafeguardForJavaException General Safeguard for Java exception.
     */
    public static ISafeguardConnection connect(String networkAddress, String certificatePath,
            char[] certificatePassword, Integer apiVersion, Boolean ignoreSsl, String provider) 
            throws ObjectDisposedException, SafeguardForJavaException {
        int version = DEFAULTAPIVERSION;
        if (apiVersion != null) {
            version = apiVersion;
        }

        boolean sslIgnore = false;
        if (ignoreSsl != null) {
            sslIgnore = ignoreSsl;
        }

        return getConnection(new CertificateAuthenticator(networkAddress, certificatePath, certificatePassword,
                version, sslIgnore, null, provider));
    }

    /**
     *  Connect to Safeguard API using a certificate stored in a file.
     *
     *  @param networkAddress Network address of Safeguard appliance.
     *  @param certificatePath Path to PFX (or PKCS12) certificate file also
     *  containing private key.
     *  @param certificatePassword Password to decrypt the certificate file.
     *  @param provider Safeguard authentication provider name (e.g. local).
     *  @param apiVersion Target API version to use.
     *  @param validationCallback Callback function to be executed during SSL certificate validation.
     * 
     *  @return Reusable Safeguard API connection.
     *  @throws ObjectDisposedException Object has already been disposed.
     *  @throws SafeguardForJavaException General Safeguard for Java exception.
     */
    public static ISafeguardConnection connect(String networkAddress, String certificatePath,
            char[] certificatePassword, HostnameVerifier validationCallback, String provider, Integer apiVersion) 
            throws ObjectDisposedException, SafeguardForJavaException {
        int version = DEFAULTAPIVERSION;
        if (apiVersion != null) {
            version = apiVersion;
        }

        return getConnection(new CertificateAuthenticator(networkAddress, certificatePath, certificatePassword,
                version, false, validationCallback, provider));
    }

    /**
     *  Connect to Safeguard API using a certificate stored in memory.
     *
     *  @param networkAddress Network address of Safeguard appliance.
     *  @param certificateData Bytes containing a PFX (or PKCS12) formatted certificate and private key.
     *  @param certificatePassword Password to decrypt the certificate data.
     *  @param certificateAlias Alias identifying a client certificate in the keystore.
     *  @param provider Safeguard authentication provider name (e.g. local).
     *  @param apiVersion Target API version to use.
     *  @param ignoreSsl Ignore server certificate validation.
     * 
     *  @return Reusable Safeguard API connection.
     *  @throws ObjectDisposedException Object has already been disposed.
     *  @throws SafeguardForJavaException General Safeguard for Java exception.
     */
    public static ISafeguardConnection connect(String networkAddress, byte[] certificateData,
            char[] certificatePassword, String certificateAlias, String provider, Integer apiVersion, Boolean ignoreSsl) 
            throws ObjectDisposedException, SafeguardForJavaException {
        int version = DEFAULTAPIVERSION;
        if (apiVersion != null) {
            version = apiVersion;
        }

        boolean sslIgnore = false;
        if (ignoreSsl != null) {
            sslIgnore = ignoreSsl;
        }

        return getConnection(new CertificateAuthenticator(networkAddress, certificateData, certificatePassword, certificateAlias,
                version, sslIgnore, null, provider));
    }
    
    /**
     *  Connect to Safeguard API using a certificate stored in memory.
     *
     *  @param networkAddress Network address of Safeguard appliance.
     *  @param certificateData Bytes containing a PFX (or PKCS12) formatted certificate and private key.
     *  @param certificatePassword Password to decrypt the certificate data.
     *  @param certificateAlias Alias identifying a client certificate in the keystore.
     *  @param provider Safeguard authentication provider name (e.g. local).
     *  @param apiVersion Target API version to use.
     *  @param validationCallback Callback function to be executed during SSL certificate validation.
     * 
     *  @return Reusable Safeguard API connection.
     *  @throws ObjectDisposedException Object has already been disposed.
     *  @throws SafeguardForJavaException General Safeguard for Java exception.
     */
    public static ISafeguardConnection connect(String networkAddress, byte[] certificateData,
            char[] certificatePassword, String certificateAlias, HostnameVerifier validationCallback,
            String provider, Integer apiVersion) 
            throws ObjectDisposedException, SafeguardForJavaException {
        int version = DEFAULTAPIVERSION;
        if (apiVersion != null) {
            version = apiVersion;
        }

        return getConnection(new CertificateAuthenticator(networkAddress, certificateData, certificatePassword, certificateAlias,
                version, false, validationCallback, provider));
    }
    
    /**
     *  Connect to Safeguard API anonymously.
     *
     *  @param networkAddress Network address.
     *  @param apiVersion API version.
     *  @param ignoreSsl If set to <code>true</code> ignore ssl.
     * 
     *  @return Reusable Safeguard API connection.
     *  @throws SafeguardForJavaException General Safeguard for Java exception.
     */
    public static ISafeguardConnection connect(String networkAddress, Integer apiVersion, Boolean ignoreSsl) 
            throws SafeguardForJavaException {
        int version = DEFAULTAPIVERSION;
        if (apiVersion != null) {
            version = apiVersion;
        }

        boolean sslIgnore = false;
        if (ignoreSsl != null) {
            sslIgnore = ignoreSsl;
        }

        // Don't try to refresh access token on the anonymous connect method because it cannot be refreshed
        // So, don't use GetConnection() function above
        return new SafeguardConnection(new AnonymousAuthenticator(networkAddress, version, sslIgnore, null));
    }

    /**
     *  Connect to Safeguard API anonymously.
     *
     *  @param networkAddress Network address.
     *  @param apiVersion API version.
     *  @param validationCallback Callback function to be executed during SSL certificate validation.
     * 
     *  @return Reusable Safeguard API connection.
     *  @throws SafeguardForJavaException General Safeguard for Java exception.
     */
    public static ISafeguardConnection connect(String networkAddress, HostnameVerifier validationCallback, Integer apiVersion) 
            throws SafeguardForJavaException {
        int version = DEFAULTAPIVERSION;
        if (apiVersion != null) {
            version = apiVersion;
        }

        // Don't try to refresh access token on the anonymous connect method because it cannot be refreshed
        // So, don't use GetConnection() function above
        return new SafeguardConnection(new AnonymousAuthenticator(networkAddress, version, false, validationCallback));
    }
    
    /**
     *  Create a persistent connection to the Safeguard API that automatically renews expired access tokens.
     * 
     *  @param connection Connection to be made persistent.
     *  @return Reusable persistent Safeguard API connection.
     */ 
    public static ISafeguardConnection Persist(ISafeguardConnection connection)
    {
        return new PersistentSafeguardConnection(connection);
    }

    /**
     *  This static class provides access to Safeguard Event functionality with
     *  persistent event listeners. Persistent event listeners can handle longer
     *  term service outages to reconnect SignalR even after it times out. It is
     *  recommended to use these interfaces when listening for Safeguard events
     *  from a long-running service.
     */
    public static class Event {

        /**
         *  Get a persistent event listener using a username and password
         *  credential for authentication.
         *
         *  @param networkAddress Network address of Safeguard appliance.
         *  @param provider Safeguard authentication provider name (e.g. local).
         *  @param username User name to use for authentication.
         *  @param password User password to use for authentication.
         *  @param apiVersion Target API version to use.
         *  @param ignoreSsl Ignore server certificate validation.
         * 
         *  @return New persistent Safeguard event listener.
         *  @throws ObjectDisposedException Object has already been disposed.
         *  @throws SafeguardForJavaException General Safeguard for Java
         *  @throws ArgumentException Invalid argument.
         *  exception.
         */
        public static ISafeguardEventListener getPersistentEventListener(String networkAddress, String provider,
                String username, char[] password, Integer apiVersion, Boolean ignoreSsl)
                throws ObjectDisposedException, SafeguardForJavaException, ArgumentException {
            
            int version = DEFAULTAPIVERSION;
            if (apiVersion != null) {
                version = apiVersion;
            }

            boolean sslIgnore = false;
            if (ignoreSsl != null) {
                sslIgnore = ignoreSsl;
            }

            return new PersistentSafeguardEventListener(getConnection(
                    new PasswordAuthenticator(networkAddress, provider, username, password, version, ignoreSsl, null)));
        }

        /**
         *  Get a persistent event listener using a username and password
         *  credential for authentication.
         *
         *  @param networkAddress Network address of Safeguard appliance.
         *  @param provider Safeguard authentication provider name (e.g. local).
         *  @param username User name to use for authentication.
         *  @param password User password to use for authentication.
         *  @param apiVersion Target API version to use.
         *  @param validationCallback Callback function to be executed during SSL certificate validation.
         * 
         *  @return New persistent Safeguard event listener.
         *  @throws ObjectDisposedException Object has already been disposed.
         *  @throws SafeguardForJavaException General Safeguard for Java
         *  @throws ArgumentException Invalid argument.
         *  exception.
         */
        public static ISafeguardEventListener getPersistentEventListener(String networkAddress, String provider,
                String username, char[] password, HostnameVerifier validationCallback, Integer apiVersion)
                throws ObjectDisposedException, SafeguardForJavaException, ArgumentException {
            
            int version = DEFAULTAPIVERSION;
            if (apiVersion != null) {
                version = apiVersion;
            }

            return new PersistentSafeguardEventListener(getConnection(
                    new PasswordAuthenticator(networkAddress, provider, username, password, version, false, validationCallback)));
        }

        /**
         *  Get a persistent event listener using a client certificate stored in
         *  a file.
         *
         *  @param networkAddress Network address of Safeguard appliance.
         *  @param certificatePath Path to PFX (or PKCS12) certificate file also
         *  containing private key.
         *  @param certificatePassword Password to decrypt the certificate file.
         *  @param apiVersion Target API version to use.
         *  @param ignoreSsl Ignore server certificate validation.
         * 
         *  @return New persistent Safeguard event listener.
         *  @throws ObjectDisposedException Object has already been disposed.
         *  @throws SafeguardForJavaException General Safeguard for Java
         *  exception.
         */
        public static ISafeguardEventListener getPersistentEventListener(String networkAddress, String certificatePath,
                char[] certificatePassword, Integer apiVersion, Boolean ignoreSsl)
                throws ObjectDisposedException, SafeguardForJavaException {
            int version = DEFAULTAPIVERSION;
            if (apiVersion != null) {
                version = apiVersion;
            }

            boolean sslIgnore = false;
            if (ignoreSsl != null) {
                sslIgnore = ignoreSsl;
            }

            return new PersistentSafeguardEventListener(getConnection(
                    new CertificateAuthenticator(networkAddress, certificatePath, certificatePassword, version, ignoreSsl, null)));
        }

        /**
         *  Get a persistent event listener using a client certificate stored in
         *  a file.
         *
         *  @param networkAddress Network address of Safeguard appliance.
         *  @param certificatePath Path to PFX (or PKCS12) certificate file also
         *  containing private key.
         *  @param certificatePassword Password to decrypt the certificate file.
         *  @param apiVersion Target API version to use.
         *  @param validationCallback Callback function to be executed during SSL certificate validation.
         * 
         *  @return New persistent Safeguard event listener.
         *  @throws ObjectDisposedException Object has already been disposed.
         *  @throws SafeguardForJavaException General Safeguard for Java
         *  exception.
         */
        public static ISafeguardEventListener getPersistentEventListener(String networkAddress, String certificatePath,
                char[] certificatePassword, HostnameVerifier validationCallback, Integer apiVersion)
                throws ObjectDisposedException, SafeguardForJavaException {
            int version = DEFAULTAPIVERSION;
            if (apiVersion != null) {
                version = apiVersion;
            }

            return new PersistentSafeguardEventListener(getConnection(
                    new CertificateAuthenticator(networkAddress, certificatePath, certificatePassword, version, false, validationCallback)));
        }

        /**
         *  Get a persistent event listener using a client certificate stored in memory.
         *
         *  @param networkAddress Network address of Safeguard appliance.
         *  @param certificateData Bytes containing a PFX (or PKCS12) formatted certificate and private key.
         *  @param certificatePassword Password to decrypt the certificate file.
         *  @param certificateAlias Alias identifying a client certificate in the keystore.
         *  @param apiVersion Target API version to use.
         *  @param ignoreSsl Ignore server certificate validation.
         * 
         *  @return New persistent Safeguard event listener.
         *  @throws ObjectDisposedException Object has already been disposed.
         *  @throws SafeguardForJavaException General Safeguard for Java
         *  exception.
         */
        public static ISafeguardEventListener getPersistentEventListener(String networkAddress, byte[] certificateData,
                char[] certificatePassword, String certificateAlias, Integer apiVersion, Boolean ignoreSsl)
                throws ObjectDisposedException, SafeguardForJavaException {
            int version = DEFAULTAPIVERSION;
            if (apiVersion != null) {
                version = apiVersion;
            }

            boolean sslIgnore = false;
            if (ignoreSsl != null) {
                sslIgnore = ignoreSsl;
            }

            return new PersistentSafeguardEventListener(getConnection(
                    new CertificateAuthenticator(networkAddress, certificateData, certificatePassword, certificateAlias, version, ignoreSsl, null)));
        }
        
        /**
         *  Get a persistent event listener using a client certificate stored in memory.
         *
         *  @param networkAddress Network address of Safeguard appliance.
         *  @param certificateData Bytes containing a PFX (or PKCS12) formatted certificate and private key.
         *  @param certificatePassword Password to decrypt the certificate file.
         *  @param certificateAlias Alias identifying a client certificate in the keystore.
         *  @param apiVersion Target API version to use.
         *  @param validationCallback Callback function to be executed during SSL certificate validation.
         * 
         *  @return New persistent Safeguard event listener.
         *  @throws ObjectDisposedException Object has already been disposed.
         *  @throws SafeguardForJavaException General Safeguard for Java
         *  exception.
         */
        public static ISafeguardEventListener getPersistentEventListener(String networkAddress, byte[] certificateData,
                char[] certificatePassword, String certificateAlias, HostnameVerifier validationCallback, Integer apiVersion)
                throws ObjectDisposedException, SafeguardForJavaException {
            int version = DEFAULTAPIVERSION;
            if (apiVersion != null) {
                version = apiVersion;
            }

            return new PersistentSafeguardEventListener(getConnection(
                    new CertificateAuthenticator(networkAddress, certificateData, certificatePassword, certificateAlias, version, false, validationCallback)));
        }
        
        /**
         *  Get a persistent event listener using a client certificate from the
         *  certificate keystore for authentication.
         *
         *  @param networkAddress Network address of Safeguard appliance.
         *  @param keystorePath Path to the keystore containing the client certificate.
         *  @param keystorePassword Keystore password.
         *  @param certificateAlias Alias identifying a client certificate in the keystore.
         *  @param apiVersion Target API version to use.
         *  @param ignoreSsl Ignore server certificate validation.
         * 
         *  @return New persistent Safeguard event listener.
         *  @throws ObjectDisposedException Object has already been disposed.
         *  @throws SafeguardForJavaException General Safeguard for Java exception.
         */
        public static ISafeguardEventListener getPersistentEventListener(String networkAddress,
                String keystorePath, char[] keystorePassword, String certificateAlias, Integer apiVersion, Boolean ignoreSsl)
                throws ObjectDisposedException, SafeguardForJavaException {
            int version = DEFAULTAPIVERSION;
            if (apiVersion != null) {
                version = apiVersion;
            }

            boolean sslIgnore = false;
            if (ignoreSsl != null) {
                sslIgnore = ignoreSsl;
            }

            return new PersistentSafeguardEventListener(getConnection(new CertificateAuthenticator(networkAddress,
                    keystorePath, keystorePassword, certificateAlias, version, ignoreSsl, null)));
        }
        
        /**
         *  Get a persistent event listener using a client certificate from the
         *  certificate keystore for authentication.
         *
         *  @param networkAddress Network address of Safeguard appliance.
         *  @param keystorePath Path to the keystore containing the client certificate.
         *  @param keystorePassword Keystore password.
         *  @param certificateAlias Alias identifying a client certificate in the keystore.
         *  @param apiVersion Target API version to use.
         *  @param validationCallback Callback function to be executed during SSL certificate validation.
         * 
         *  @return New persistent Safeguard event listener.
         *  @throws ObjectDisposedException Object has already been disposed.
         *  @throws SafeguardForJavaException General Safeguard for Java exception.
         */
        public static ISafeguardEventListener getPersistentEventListener(String networkAddress,
                String keystorePath, char[] keystorePassword, String certificateAlias, HostnameVerifier validationCallback, Integer apiVersion)
                throws ObjectDisposedException, SafeguardForJavaException {
            int version = DEFAULTAPIVERSION;
            if (apiVersion != null) {
                version = apiVersion;
            }

            return new PersistentSafeguardEventListener(getConnection(new CertificateAuthenticator(networkAddress,
                    keystorePath, keystorePassword, certificateAlias, version, false, validationCallback)));
        }

        /**
         *  Get a persistent event listener using a client certificate stored in
         *  a file.
         *
         *  @param networkAddress Network address of Safeguard appliance.
         *  @param certificatePath Path to PFX (or PKCS12) certificate file also
         *  containing private key.
         *  @param certificatePassword Password to decrypt the certificate file.
         *  @param apiVersion Target API version to use.
         *  @param ignoreSsl Ignore server certificate validation.
         *  @param provider Safeguard authentication provider name (e.g. local).
         * 
         *  @return New persistent Safeguard event listener.
         *  @throws ObjectDisposedException Object has already been disposed.
         *  @throws SafeguardForJavaException General Safeguard for Java
         *  exception.
         */
        public static ISafeguardEventListener getPersistentEventListener(String networkAddress, String certificatePath,
                char[] certificatePassword, Integer apiVersion, Boolean ignoreSsl, String provider)
                throws ObjectDisposedException, SafeguardForJavaException {
            int version = DEFAULTAPIVERSION;
            if (apiVersion != null) {
                version = apiVersion;
            }

            boolean sslIgnore = false;
            if (ignoreSsl != null) {
                sslIgnore = ignoreSsl;
            }

            return new PersistentSafeguardEventListener(getConnection(
                    new CertificateAuthenticator(networkAddress, certificatePath, certificatePassword, version, ignoreSsl, null, provider)));
        }

        /**
         *  Get a persistent event listener using a client certificate stored in
         *  a file.
         *
         *  @param networkAddress Network address of Safeguard appliance.
         *  @param certificatePath Path to PFX (or PKCS12) certificate file also
         *  containing private key.
         *  @param certificatePassword Password to decrypt the certificate file.
         *  @param provider Safeguard authentication provider name (e.g. local).
         *  @param apiVersion Target API version to use.
         *  @param validationCallback Callback function to be executed during SSL certificate validation.
         * 
         *  @return New persistent Safeguard event listener.
         *  @throws ObjectDisposedException Object has already been disposed.
         *  @throws SafeguardForJavaException General Safeguard for Java
         *  exception.
         */
        public static ISafeguardEventListener getPersistentEventListener(String networkAddress, String certificatePath,
                char[] certificatePassword, HostnameVerifier validationCallback, String provider, Integer apiVersion)
                throws ObjectDisposedException, SafeguardForJavaException {
            int version = DEFAULTAPIVERSION;
            if (apiVersion != null) {
                version = apiVersion;
            }

            return new PersistentSafeguardEventListener(getConnection(
                    new CertificateAuthenticator(networkAddress, certificatePath, certificatePassword, version, false, validationCallback, provider)));
        }

        /**
         *  Get a persistent event listener using a certificate from the Windows 
         *  certificate store. This is a Windows only API and requires that the
         *  SunMSCAPI security provider is available in the Java environment.
         *
         *  @param networkAddress Network address of Safeguard appliance.
         *  @param thumbprint Thumbprint of the client certificate.
         *  @param apiVersion Target API version to use.
         *  @param ignoreSsl Ignore server certificate validation.
         * 
         *  @return New persistent Safeguard event listener.
         *  @throws ObjectDisposedException Object has already been disposed.
         *  @throws SafeguardForJavaException General Safeguard for Java
         *  exception.
         */
        public static ISafeguardEventListener getPersistentEventListener(String networkAddress, String thumbprint,
                Integer apiVersion, Boolean ignoreSsl)
                throws ObjectDisposedException, SafeguardForJavaException {
            int version = DEFAULTAPIVERSION;
            if (apiVersion != null) {
                version = apiVersion;
            }

            boolean sslIgnore = false;
            if (ignoreSsl != null) {
                sslIgnore = ignoreSsl;
            }
            
            if (Utils.isWindows()) {
                if (!Utils.isSunMSCAPILoaded()) {
                    throw new SafeguardForJavaException("Missing SunMSCAPI provider. The SunMSCAPI provider must be added as a security provider in $JAVA_HOME/jre/lib/security/java.security configuration file.");
                }
            }
            else {
                throw new SafeguardForJavaException("Not implemented. This function is only available on the Windows platform.");
            }

            return new PersistentSafeguardEventListener(getConnection(
                    new CertificateAuthenticator(networkAddress, thumbprint, version, ignoreSsl, null, null)));
        }

        /**
         *  Get a persistent event listener using a certificate from the Windows 
         *  certificate store. This is a Windows only API and requires that the
         *  SunMSCAPI security provider is available in the Java environment.
         *
         *  @param networkAddress Network address of Safeguard appliance.
         *  @param thumbprint Thumbprint of the client certificate.
         *  @param apiVersion Target API version to use.
         *  @param validationCallback Callback function to be executed during SSL certificate validation.
         * 
         *  @return New persistent Safeguard event listener.
         *  @throws ObjectDisposedException Object has already been disposed.
         *  @throws SafeguardForJavaException General Safeguard for Java
         *  exception.
         */
        public static ISafeguardEventListener getPersistentEventListener(String networkAddress, String thumbprint,
                HostnameVerifier validationCallback, Integer apiVersion)
                throws ObjectDisposedException, SafeguardForJavaException {
            int version = DEFAULTAPIVERSION;
            if (apiVersion != null) {
                version = apiVersion;
            }
            
            if (Utils.isWindows()) {
                if (!Utils.isSunMSCAPILoaded()) {
                    throw new SafeguardForJavaException("Missing SunMSCAPI provider. The SunMSCAPI provider must be added as a security provider in $JAVA_HOME/jre/lib/security/java.security configuration file.");
                }
            }
            else {
                throw new SafeguardForJavaException("Not implemented. This function is only available on the Windows platform.");
            }

            return new PersistentSafeguardEventListener(getConnection(
                    new CertificateAuthenticator(networkAddress, thumbprint, version, false, validationCallback, null)));
        }

        /**
         *  Get a persistent event listener using a certificate from the Windows 
         *  certificate store. This is a Windows only API and requires that the
         *  SunMSCAPI security provider is available in the Java environment.
         *
         *  @param networkAddress Network address of Safeguard appliance.
         *  @param thumbprint Thumbprint of the client certificate.
         *  @param apiVersion Target API version to use.
         *  @param ignoreSsl Ignore server certificate validation.
         *  @param provider Safeguard authentication provider name (e.g. local).
         * 
         *  @return New persistent Safeguard event listener.
         *  @throws ObjectDisposedException Object has already been disposed.
         *  @throws SafeguardForJavaException General Safeguard for Java
         *  exception.
         */
        public static ISafeguardEventListener getPersistentEventListener(String networkAddress, String thumbprint,
                Integer apiVersion, Boolean ignoreSsl, String provider)
                throws ObjectDisposedException, SafeguardForJavaException {
            int version = DEFAULTAPIVERSION;
            if (apiVersion != null) {
                version = apiVersion;
            }

            boolean sslIgnore = false;
            if (ignoreSsl != null) {
                sslIgnore = ignoreSsl;
            }
            
            if (Utils.isWindows()) {
                if (!Utils.isSunMSCAPILoaded()) {
                    throw new SafeguardForJavaException("Missing SunMSCAPI provider. The SunMSCAPI provider must be added as a security provider in $JAVA_HOME/jre/lib/security/java.security configuration file.");
                }
            }
            else {
                throw new SafeguardForJavaException("Not implemented. This function is only available on the Windows platform.");
            }

            return new PersistentSafeguardEventListener(getConnection(
                    new CertificateAuthenticator(networkAddress, thumbprint, version, ignoreSsl, null, provider)));
        }

        /**
         *  Get a persistent event listener using a certificate from the Windows 
         *  certificate store. This is a Windows only API and requires that the
         *  SunMSCAPI security provider is available in the Java environment.
         *
         *  @param networkAddress Network address of Safeguard appliance.
         *  @param thumbprint Thumbprint of the client certificate.
         *  @param provider Safeguard authentication provider name (e.g. local).
         *  @param apiVersion Target API version to use.
         *  @param validationCallback Callback function to be executed during SSL certificate validation.
         * 
         *  @return New persistent Safeguard event listener.
         *  @throws ObjectDisposedException Object has already been disposed.
         *  @throws SafeguardForJavaException General Safeguard for Java
         *  exception.
         */
        public static ISafeguardEventListener getPersistentEventListener(String networkAddress, String thumbprint,
                HostnameVerifier validationCallback, String provider, Integer apiVersion)
                throws ObjectDisposedException, SafeguardForJavaException {
            int version = DEFAULTAPIVERSION;
            if (apiVersion != null) {
                version = apiVersion;
            }
            
            if (Utils.isWindows()) {
                if (!Utils.isSunMSCAPILoaded()) {
                    throw new SafeguardForJavaException("Missing SunMSCAPI provider. The SunMSCAPI provider must be added as a security provider in $JAVA_HOME/jre/lib/security/java.security configuration file.");
                }
            }
            else {
                throw new SafeguardForJavaException("Not implemented. This function is only available on the Windows platform.");
            }

            return new PersistentSafeguardEventListener(getConnection(
                    new CertificateAuthenticator(networkAddress, thumbprint, version, false, validationCallback, provider)));
        }

        /**
         *  Get a persistent event listener using a client certificate stored in memory.
         *
         *  @param networkAddress Network address of Safeguard appliance.
         *  @param certificateData Bytes containing a PFX (or PKCS12) formatted certificate and private key.
         *  @param certificatePassword Password to decrypt the certificate file.
         *  @param certificateAlias Alias identifying a client certificate in the keystore.
         *  @param provider Safeguard authentication provider name (e.g. local).
         *  @param apiVersion Target API version to use.
         *  @param ignoreSsl Ignore server certificate validation.
         * 
         *  @return New persistent Safeguard event listener.
         *  @throws ObjectDisposedException Object has already been disposed.
         *  @throws SafeguardForJavaException General Safeguard for Java
         *  exception.
         */
        public static ISafeguardEventListener getPersistentEventListener(String networkAddress, byte[] certificateData,
                char[] certificatePassword, String certificateAlias, String provider, Integer apiVersion, Boolean ignoreSsl)
                throws ObjectDisposedException, SafeguardForJavaException {
            int version = DEFAULTAPIVERSION;
            if (apiVersion != null) {
                version = apiVersion;
            }

            boolean sslIgnore = false;
            if (ignoreSsl != null) {
                sslIgnore = ignoreSsl;
            }

            return new PersistentSafeguardEventListener(getConnection(
                    new CertificateAuthenticator(networkAddress, certificateData, certificatePassword, certificateAlias, version, ignoreSsl, null, provider)));
        }
        
        /**
         *  Get a persistent event listener using a client certificate stored in memory.
         *
         *  @param networkAddress Network address of Safeguard appliance.
         *  @param certificateData Bytes containing a PFX (or PKCS12) formatted certificate and private key.
         *  @param certificatePassword Password to decrypt the certificate file.
         *  @param certificateAlias Alias identifying a client certificate in the keystore.
         *  @param provider Safeguard authentication provider name (e.g. local).
         *  @param apiVersion Target API version to use.
         *  @param validationCallback Callback function to be executed during SSL certificate validation.
         * 
         *  @return New persistent Safeguard event listener.
         *  @throws ObjectDisposedException Object has already been disposed.
         *  @throws SafeguardForJavaException General Safeguard for Java
         *  exception.
         */
        public static ISafeguardEventListener getPersistentEventListener(String networkAddress, byte[] certificateData,
                char[] certificatePassword, String certificateAlias, HostnameVerifier validationCallback,
                String provider, Integer apiVersion)
                throws ObjectDisposedException, SafeguardForJavaException {
            int version = DEFAULTAPIVERSION;
            if (apiVersion != null) {
                version = apiVersion;
            }

            return new PersistentSafeguardEventListener(getConnection(
                    new CertificateAuthenticator(networkAddress, certificateData, certificatePassword, certificateAlias, version, false, validationCallback, provider)));
        }
        
        /**
         *  Get a persistent event listener using a client certificate from the
         *  certificate keystore for authentication.
         *
         *  @param networkAddress Network address of Safeguard appliance.
         *  @param keystorePath Path to the keystore containing the client certificate.
         *  @param keystorePassword Keystore password.
         *  @param certificateAlias Alias identifying a client certificate in the keystore.
         *  @param provider Safeguard authentication provider name (e.g. local).
         *  @param apiVersion Target API version to use.
         *  @param ignoreSsl Ignore server certificate validation.
         * 
         *  @return New persistent Safeguard event listener.
         *  @throws ObjectDisposedException Object has already been disposed.
         *  @throws SafeguardForJavaException General Safeguard for Java exception.
         */
        public static ISafeguardEventListener getPersistentEventListener(String networkAddress,
                String keystorePath, char[] keystorePassword, String certificateAlias,
                String provider, Integer apiVersion, Boolean ignoreSsl)
                throws ObjectDisposedException, SafeguardForJavaException {
            int version = DEFAULTAPIVERSION;
            if (apiVersion != null) {
                version = apiVersion;
            }

            boolean sslIgnore = false;
            if (ignoreSsl != null) {
                sslIgnore = ignoreSsl;
            }

            return new PersistentSafeguardEventListener(getConnection(new CertificateAuthenticator(networkAddress,
                    keystorePath, keystorePassword, certificateAlias, version, ignoreSsl, null, provider)));
        }
        
        /**
         *  Get a persistent event listener using a client certificate from the
         *  certificate keystore for authentication.
         *
         *  @param networkAddress Network address of Safeguard appliance.
         *  @param keystorePath Path to the keystore containing the client certificate.
         *  @param keystorePassword Keystore password.
         *  @param certificateAlias Alias identifying a client certificate in the keystore.
         *  @param provider Safeguard authentication provider name (e.g. local).
         *  @param apiVersion Target API version to use.
         *  @param validationCallback Callback function to be executed during SSL certificate validation.
         * 
         *  @return New persistent Safeguard event listener.
         *  @throws ObjectDisposedException Object has already been disposed.
         *  @throws SafeguardForJavaException General Safeguard for Java exception.
         */
        public static ISafeguardEventListener getPersistentEventListener(String networkAddress,
                String keystorePath, char[] keystorePassword, String certificateAlias, 
                HostnameVerifier validationCallback, String provider, Integer apiVersion)
                throws ObjectDisposedException, SafeguardForJavaException {
            int version = DEFAULTAPIVERSION;
            if (apiVersion != null) {
                version = apiVersion;
            }

            return new PersistentSafeguardEventListener(getConnection(new CertificateAuthenticator(networkAddress,
                    keystorePath, keystorePassword, certificateAlias, version, false, validationCallback, provider)));
        }
    }

    /**
     * This static class provides access to Safeguard A2A functionality.
     *
     */
    public static class A2A {

        /**
         *  Establish a Safeguard A2A context using a client certificate from the keystore.
         *
         *  @param networkAddress Network address of Safeguard appliance.
         *  @param keystorePath Path to the keystore containing the client certificate.
         *  @param keystorePassword Keystore password.
         *  @param certificateAlias Alias identifying a client certificate in the keystore.
         *  @param apiVersion Target API version to use.
         *  @param ignoreSsl Ignore server certificate validation.
         * 
         *  @return Reusable Safeguard A2A context.
         */
        public static ISafeguardA2AContext getContext(String networkAddress, String keystorePath, char[] keystorePassword, String certificateAlias,
                Integer apiVersion, Boolean ignoreSsl) {
            int version = DEFAULTAPIVERSION;
            if (apiVersion != null) {
                version = apiVersion;
            }

            boolean sslIgnore = false;
            if (ignoreSsl != null) {
                sslIgnore = ignoreSsl;
            }

            return new SafeguardA2AContext(networkAddress, certificateAlias, keystorePath, keystorePassword, version, sslIgnore, null);
        }

        /**
         *  Establish a Safeguard A2A context using a client certificate from the keystore.
         *
         *  @param networkAddress Network address of Safeguard appliance.
         *  @param keystorePath Path to the keystore containing the client certificate.
         *  @param keystorePassword Keystore password.
         *  @param certificateAlias Alias identifying a client certificate in the keystore.
         *  @param apiVersion Target API version to use.
         *  @param validationCallback Callback function to be executed during SSL certificate validation.
         * 
         *  @return Reusable Safeguard A2A context.
         */
        public static ISafeguardA2AContext getContext(String networkAddress, String keystorePath, char[] keystorePassword, String certificateAlias,
                HostnameVerifier validationCallback, Integer apiVersion) {
            int version = DEFAULTAPIVERSION;
            if (apiVersion != null) {
                version = apiVersion;
            }

            return new SafeguardA2AContext(networkAddress, certificateAlias, keystorePath, keystorePassword, version, false, validationCallback);
        }

        /**
         *  Establish a Safeguard A2A context using a certificate from the Windows 
         *  certificate store. This is a Windows only API and requires that the
         *  SunMSCAPI security provider is available in the Java environment.
         *
         *  @param networkAddress Network address of Safeguard appliance.
         *  @param thumbprint Thumbprint of the client certificate.
         *  @param apiVersion Target API version to use.
         *  @param ignoreSsl Ignore server certificate validation.
         * 
         *  @return Reusable Safeguard A2A context.
         *  @throws SafeguardForJavaException General Safeguard for Java exception.
         */
        public static ISafeguardA2AContext getContext(String networkAddress, String thumbprint,
                Integer apiVersion, Boolean ignoreSsl) throws SafeguardForJavaException {
            int version = DEFAULTAPIVERSION;
            if (apiVersion != null) {
                version = apiVersion;
            }

            boolean sslIgnore = false;
            if (ignoreSsl != null) {
                sslIgnore = ignoreSsl;
            }

            if (Utils.isWindows()) {
                if (!Utils.isSunMSCAPILoaded()) {
                    throw new SafeguardForJavaException("Missing SunMSCAPI provider. The SunMSCAPI provider must be added as a security provider in $JAVA_HOME/jre/lib/security/java.security configuration file.");
                }
            }
            else {
                throw new SafeguardForJavaException("Not implemented. This function is only available on the Windows platform.");
            }
        
            return new SafeguardA2AContext(networkAddress, version, sslIgnore, thumbprint, null);
        }

        /**
         *  Establish a Safeguard A2A context using a certificate from the Windows 
         *  certificate store. This is a Windows only API and requires that the
         *  SunMSCAPI security provider is available in the Java environment.
         *
         *  @param networkAddress Network address of Safeguard appliance.
         *  @param thumbprint Thumbprint of the client certificate.
         *  @param apiVersion Target API version to use.
         *  @param validationCallback Callback function to be executed during SSL certificate validation.
         * 
         *  @return Reusable Safeguard A2A context.
         *  @throws SafeguardForJavaException General Safeguard for Java exception.
         */
        public static ISafeguardA2AContext getContext(String networkAddress, String thumbprint,
                HostnameVerifier validationCallback, Integer apiVersion) throws SafeguardForJavaException {
            int version = DEFAULTAPIVERSION;
            if (apiVersion != null) {
                version = apiVersion;
            }
            
            if (Utils.isWindows()) {
                if (!Utils.isSunMSCAPILoaded()) {
                    throw new SafeguardForJavaException("Missing SunMSCAPI provider. The SunMSCAPI provider must be added as a security provider in $JAVA_HOME/jre/lib/security/java.security configuration file.");
                }
            }
            else {
                throw new SafeguardForJavaException("Not implemented. This function is only available on the Windows platform.");
            }

            return new SafeguardA2AContext(networkAddress, version, false, thumbprint, validationCallback);
        }

        /**
         *  Establish a Safeguard A2A context using a client certificate stored in a file.
         *
         *  @param networkAddress Network address of Safeguard appliance.
         *  @param certificatePath Path to PFX (or PKCS12) certificate file also
         *  containing private key.
         *  @param certificatePassword Password to decrypt the certificate file.
         *  @param apiVersion Target API version to use.
         *  @param ignoreSsl Ignore server certificate validation.
         * 
         *  @return Reusable Safeguard A2A context.
         */
        public static ISafeguardA2AContext getContext(String networkAddress, String certificatePath,
                char[] certificatePassword, Integer apiVersion, Boolean ignoreSsl) {
            int version = DEFAULTAPIVERSION;
            if (apiVersion != null) {
                version = apiVersion;
            }

            boolean sslIgnore = false;
            if (ignoreSsl != null) {
                sslIgnore = ignoreSsl;
            }

            return new SafeguardA2AContext(networkAddress, certificatePath, certificatePassword, version, sslIgnore, null);
        }

        /**
         *  Establish a Safeguard A2A context using a client certificate stored in a file.
         *
         *  @param networkAddress Network address of Safeguard appliance.
         *  @param certificatePath Path to PFX (or PKCS12) certificate file also
         *  containing private key.
         *  @param certificatePassword Password to decrypt the certificate file.
         *  @param apiVersion Target API version to use.
         *  @param validationCallback Callback function to be executed during SSL certificate validation.
         * 
         *  @return Reusable Safeguard A2A context.
         */
        public static ISafeguardA2AContext getContext(String networkAddress, String certificatePath,
                char[] certificatePassword, HostnameVerifier validationCallback, Integer apiVersion) {
            int version = DEFAULTAPIVERSION;
            if (apiVersion != null) {
                version = apiVersion;
            }

            return new SafeguardA2AContext(networkAddress, certificatePath, certificatePassword, version, false, validationCallback);
        }

        /**
         *  Establish a Safeguard A2A context using a client certificate stored in memory.
         *
         *  @param networkAddress Network address of Safeguard appliance.
         *  @param certificateData Bytes containing a PFX (or PKCS12) formatted certificate and private key.
         *  @param certificatePassword Password to decrypt the certificate file.
         *  @param apiVersion Target API version to use.
         *  @param ignoreSsl Ignore server certificate validation.
         * 
         *  @return Reusable Safeguard A2A context.
         */
        public static ISafeguardA2AContext getContext(String networkAddress, byte[] certificateData,
                char[] certificatePassword, Integer apiVersion, Boolean ignoreSsl) {
            int version = DEFAULTAPIVERSION;
            if (apiVersion != null) {
                version = apiVersion;
            }

            boolean sslIgnore = false;
            if (ignoreSsl != null) {
                sslIgnore = ignoreSsl;
            }

            return new SafeguardA2AContext(networkAddress, certificateData, certificatePassword, version, sslIgnore, null);
        }
        
        /**
         *  Establish a Safeguard A2A context using a client certificate stored in memory.
         *
         *  @param networkAddress Network address of Safeguard appliance.
         *  @param certificateData Bytes containing a PFX (or PKCS12) formatted certificate and private key.
         *  @param certificatePassword Password to decrypt the certificate file.
         *  @param apiVersion Target API version to use.
         *  @param validationCallback Callback function to be executed during SSL certificate validation.
         * 
         *  @return Reusable Safeguard A2A context.
         */
        public static ISafeguardA2AContext getContext(String networkAddress, byte[] certificateData,
                char[] certificatePassword, HostnameVerifier validationCallback, Integer apiVersion) {
            int version = DEFAULTAPIVERSION;
            if (apiVersion != null) {
                version = apiVersion;
            }

            return new SafeguardA2AContext(networkAddress, certificateData, certificatePassword, version, false, validationCallback);
        }
        
        /**
         * This static class provides access to Safeguard A2A Event
         * functionality with persistent event listeners. Persistent event
         * listeners can handle longer term service outages to reconnect SignalR
         * even after it times out. It is recommended to use these interfaces
         * when listening for Safeguard events from a long-running service.
         */
        public static class Event {

            /**
             *  Get a persistent A2A event listener. The handler passed 
             *  in will be registered for the AssetAccountPasswordUpdated 
             *  event, which is the only one supported in A2A. Uses a 
             *  client certificate in a keystore.
             *
             *  @param apiKey API key corresponding to the configured account to
             *  listen for.
             *  @param handler A delegate to call any time the
             *  AssetAccountPasswordUpdate event occurs.
             *  @param networkAddress Network address of Safeguard appliance.
             *  @param keystorePath Path to the keystore containing the client
             *  certificate.
             *  @param keystorePassword Keystore password.
             *  @param certificateAlias Alias identifying a client certificate in
             *  the keystore.
             *  @param apiVersion Target API version to use.
             *  @param ignoreSsl Ignore server certificate validation.
             * 
             *  @return New persistent A2A event listener.
             *  @throws ObjectDisposedException Object has already been disposed.
             *  @throws ArgumentException Invalid argument.
             */
            public static ISafeguardEventListener getPersistentA2AEventListener(char[] apiKey, ISafeguardEventHandler handler,
                    String networkAddress, String keystorePath, char[] keystorePassword, String certificateAlias,
                    Integer apiVersion, Boolean ignoreSsl)
                    throws ObjectDisposedException, ArgumentException {
                int version = DEFAULTAPIVERSION;
                if (apiVersion != null) {
                    version = apiVersion;
                }

                boolean sslIgnore = false;
                if (ignoreSsl != null) {
                    sslIgnore = ignoreSsl;
                }

                return new PersistentSafeguardA2AEventListener(
                        new SafeguardA2AContext(networkAddress, certificateAlias, keystorePath, keystorePassword, version, ignoreSsl, null),
                        apiKey, handler);
            }

            /**
             *  Get a persistent A2A event listener. The handler passed in 
             *  will be registered for the AssetAccountPasswordUpdated event, 
             *  which is the only one supported in A2A. Uses a client 
             *  certificate the keystore.
             *
             *  @param apiKey API key corresponding to the configured account to
             *  listen for.
             *  @param handler A delegate to call any time the
             *  AssetAccountPasswordUpdate event occurs.
             *  @param networkAddress Network address of Safeguard appliance.
             *  @param keystorePath Path to the keystore containing the client
             *  certificate.
             *  @param keystorePassword Keystore password.
             *  @param certificateAlias Alias identifying a client certificate in
             *  the keystore.
             *  @param apiVersion Target API version to use.
             *  @param validationCallback Callback function to be executed during SSL certificate validation.
             * 
             *  @return New persistent A2A event listener.
             *  @throws ObjectDisposedException Object has already been disposed.
             *  @throws ArgumentException Invalid argument.
             */
            public static ISafeguardEventListener getPersistentA2AEventListener(char[] apiKey, ISafeguardEventHandler handler,
                    String networkAddress, String keystorePath, char[] keystorePassword, String certificateAlias,
                    HostnameVerifier validationCallback, Integer apiVersion)
                    throws ObjectDisposedException, ArgumentException {
                int version = DEFAULTAPIVERSION;
                if (apiVersion != null) {
                    version = apiVersion;
                }

                return new PersistentSafeguardA2AEventListener(
                        new SafeguardA2AContext(networkAddress, certificateAlias, keystorePath, keystorePassword, version, false, validationCallback),
                        apiKey, handler);
            }

            /**
             *  Get a persistent A2A event listener. The handler passed in 
             *  will be registered for the AssetAccountPasswordUpdated event, 
             *  which is the only one supported in A2A. Uses a client 
             *  certificate from a file.
             *
             *  @param apiKey API key corresponding to the configured account to
             *  listen for.
             *  @param handler A delegate to call any time the
             *  AssetAccountPasswordUpdate event occurs.
             *  @param networkAddress Network address of Safeguard appliance.
             *  @param certificatePath Path to PFX (or PKCS12) certificate file
             *  also containing private key.
             *  @param certificatePassword Password to decrypt the certificate file.
             *  @param apiVersion Target API version to use.
             *  @param ignoreSsl Ignore server certificate validation.
             * 
             *  @return New persistent A2A event listener.
             *  @throws ObjectDisposedException Object has already been disposed.
             *  @throws ArgumentException Invalid argument.
             */
            public static ISafeguardEventListener getPersistentA2AEventListener(char[] apiKey,
                    ISafeguardEventHandler handler, String networkAddress, String certificatePath,
                    char[] certificatePassword, Integer apiVersion, Boolean ignoreSsl)
                    throws ObjectDisposedException, ArgumentException {
                
                int version = DEFAULTAPIVERSION;
                if (apiVersion != null) {
                    version = apiVersion;
                }

                boolean sslIgnore = false;
                if (ignoreSsl != null) {
                    sslIgnore = ignoreSsl;
                }

                return new PersistentSafeguardA2AEventListener(
                        new SafeguardA2AContext(networkAddress, certificatePath, certificatePassword, version,
                                ignoreSsl, null), apiKey, handler);
            }
            
            /**
             *  Get a persistent A2A event listener. The handler passed in 
             *  will be registered for the AssetAccountPasswordUpdated event, 
             *  which is the only one supported in A2A. Uses a client 
             *  certificate from a file.
             *
             *  @param apiKey API key corresponding to the configured account to
             *  listen for.
             *  @param handler A delegate to call any time the
             *  AssetAccountPasswordUpdate event occurs.
             *  @param networkAddress Network address of Safeguard appliance.
             *  @param certificatePath Path to PFX (or PKCS12) certificate file
             *  also containing private key.
             *  @param certificatePassword Password to decrypt the certificate file.
             *  @param apiVersion Target API version to use.
             *  @param validationCallback Callback function to be executed during SSL certificate validation.
             * 
             *  @return New persistent A2A event listener.
             *  @throws ObjectDisposedException Object has already been disposed.
             *  @throws ArgumentException Invalid argument.
             */
            public static ISafeguardEventListener getPersistentA2AEventListener(char[] apiKey,
                    ISafeguardEventHandler handler, String networkAddress, String certificatePath,
                    char[] certificatePassword, HostnameVerifier validationCallback, Integer apiVersion)
                    throws ObjectDisposedException, ArgumentException {
                
                int version = DEFAULTAPIVERSION;
                if (apiVersion != null) {
                    version = apiVersion;
                }

                return new PersistentSafeguardA2AEventListener(
                        new SafeguardA2AContext(networkAddress, certificatePath, certificatePassword, version,
                                false, validationCallback), apiKey, handler);
            }
            
            /**
             *  Get a persistent A2A event listener. The handler passed in 
             *  will be registered for the AssetAccountPasswordUpdated event, 
             *  which is the only one supported in A2A. Uses a client 
             *  certificate stored in memory.
             *
             *  @param apiKey API key corresponding to the configured account to
             *  listen for.
             *  @param handler A delegate to call any time the
             *  AssetAccountPasswordUpdate event occurs.
             *  @param networkAddress Network address of Safeguard appliance.
             *  @param certificateData Bytes containing a PFX (or PKCS12) formatted certificate and private key.
             *  @param certificatePassword Password to decrypt the certificate file.
             *  @param apiVersion Target API version to use.
             *  @param ignoreSsl Ignore server certificate validation.
             * 
             *  @return New persistent A2A event listener.
             *  @throws ObjectDisposedException Object has already been disposed.
             *  @throws ArgumentException Invalid argument.
             */
            public static ISafeguardEventListener getPersistentA2AEventListener(char[] apiKey,
                    ISafeguardEventHandler handler, String networkAddress, byte[] certificateData,
                    char[] certificatePassword, Integer apiVersion, Boolean ignoreSsl)
                    throws ObjectDisposedException, ArgumentException {
                
                int version = DEFAULTAPIVERSION;
                if (apiVersion != null) {
                    version = apiVersion;
                }

                boolean sslIgnore = false;
                if (ignoreSsl != null) {
                    sslIgnore = ignoreSsl;
                }

                return new PersistentSafeguardA2AEventListener(
                        new SafeguardA2AContext(networkAddress, certificateData, certificatePassword, version,
                                ignoreSsl, null), apiKey, handler);
            }
            
            /**
             *  Get a persistent A2A event listener. The handler passed in 
             *  will be registered for the AssetAccountPasswordUpdated event, 
             *  which is the only one supported in A2A. Uses a client 
             *  certificate stored in memory.
             *
             *  @param apiKey API key corresponding to the configured account to
             *  listen for.
             *  @param handler A delegate to call any time the
             *  AssetAccountPasswordUpdate event occurs.
             *  @param networkAddress Network address of Safeguard appliance.
             *  @param certificateData Bytes containing a PFX (or PKCS12) formatted certificate and private key.
             *  @param certificatePassword Password to decrypt the certificate file.
             *  @param apiVersion Target API version to use.
             *  @param validationCallback Callback function to be executed during SSL certificate validation.
             * 
             *  @return New persistent A2A event listener.
             *  @throws ObjectDisposedException Object has already been disposed.
             *  @throws ArgumentException Invalid argument.
             */
            public static ISafeguardEventListener getPersistentA2AEventListener(char[] apiKey,
                    ISafeguardEventHandler handler, String networkAddress, byte[] certificateData,
                    char[] certificatePassword, HostnameVerifier validationCallback, Integer apiVersion)
                    throws ObjectDisposedException, ArgumentException {
                
                int version = DEFAULTAPIVERSION;
                if (apiVersion != null) {
                    version = apiVersion;
                }

                return new PersistentSafeguardA2AEventListener(
                        new SafeguardA2AContext(networkAddress, certificateData, certificatePassword, version,
                                false, validationCallback), apiKey, handler);
            }
            
            /**
             *  Get a persistent A2A event listener. The handler passed in 
             *  will be registered for the AssetAccountPasswordUpdated event, 
             *  which is the only one supported in A2A. Uses a client 
             *  certificate from a keystore.
             *
             *  @param apiKeys A list of API keys corresponding to the configured accounts to
             *  listen for.
             *  @param handler A delegate to call any time the
             *  AssetAccountPasswordUpdate event occurs.
             *  @param networkAddress Network address of Safeguard appliance.
             *  @param keystorePath Path to the keystore containing the client
             *  certificate.
             *  @param keystorePassword Keystore password.
             *  @param certificateAlias Alias identifying a client certificate in
             *  the keystore.
             *  @param apiVersion Target API version to use.
             *  @param ignoreSsl Ignore server certificate validation.
             * 
             *  @return New persistent A2A event listener.
             *  @throws ObjectDisposedException Object has already been disposed.
             *  @throws ArgumentException Invalid argument.
             */
            public static ISafeguardEventListener getPersistentA2AEventListener(List<char[]> apiKeys, ISafeguardEventHandler handler,
                    String networkAddress, String keystorePath, char[] keystorePassword, String certificateAlias,
                    Integer apiVersion, Boolean ignoreSsl)
                    throws ObjectDisposedException, ArgumentException {
                int version = DEFAULTAPIVERSION;
                if (apiVersion != null) {
                    version = apiVersion;
                }

                boolean sslIgnore = false;
                if (ignoreSsl != null) {
                    sslIgnore = ignoreSsl;
                }

                return new PersistentSafeguardA2AEventListener(
                        new SafeguardA2AContext(networkAddress, certificateAlias, keystorePath, keystorePassword, version, ignoreSsl, null),
                        apiKeys, handler);
            }

            /**
             *  Get a persistent A2A event listener. The handler passed in 
             *  will be registered for the AssetAccountPasswordUpdated event, 
             *  which is the only one supported in A2A. Uses a client 
             *  certificate from a keystore.
             *
             *  @param apiKeys A list of API keys corresponding to the configured accounts to
             *  listen for.
             *  @param handler A delegate to call any time the
             *  AssetAccountPasswordUpdate event occurs.
             *  @param networkAddress Network address of Safeguard appliance.
             *  @param keystorePath Path to the keystore containing the client
             *  certificate.
             *  @param keystorePassword Keystore password.
             *  @param certificateAlias Alias identifying a client certificate in
             *  the keystore.
             *  @param apiVersion Target API version to use.
             *  @param validationCallback Callback function to be executed during SSL certificate validation.
             * 
             *  @return New persistent A2A event listener.
             *  @throws ObjectDisposedException Object has already been disposed.
             *  @throws ArgumentException Invalid argument.
             */
            public static ISafeguardEventListener getPersistentA2AEventListener(List<char[]> apiKeys, ISafeguardEventHandler handler,
                    String networkAddress, String keystorePath, char[] keystorePassword, String certificateAlias,
                    HostnameVerifier validationCallback, Integer apiVersion)
                    throws ObjectDisposedException, ArgumentException {
                int version = DEFAULTAPIVERSION;
                if (apiVersion != null) {
                    version = apiVersion;
                }

                return new PersistentSafeguardA2AEventListener(
                        new SafeguardA2AContext(networkAddress, certificateAlias, keystorePath, keystorePassword, version, false, validationCallback),
                        apiKeys, handler);
            }

            /**
             *  Get a persistent A2A event listener. The handler passed in 
             *  will be registered for the AssetAccountPasswordUpdated event, 
             *  which is the only one supported in A2A. Uses a client 
             *  certificate stored in a file.
             *
             *  @param apiKeys A list of API key corresponding to the configured accounts to
             *  listen for.
             *  @param handler A delegate to call any time the
             *  AssetAccountPasswordUpdate event occurs.
             *  @param networkAddress Network address of Safeguard appliance.
             *  @param certificatePath Path to PFX (or PKCS12) certificate file
             *  also containing private key.
             *  @param certificatePassword Password to decrypt the certificate file.
             *  @param apiVersion Target API version to use.
             *  @param ignoreSsl Ignore server certificate validation.
             * 
             *  @return New persistent A2A event listener.
             *  @throws ObjectDisposedException Object has already been disposed.
             *  @throws ArgumentException Invalid argument.
             */
            public static ISafeguardEventListener getPersistentA2AEventListener(List<char[]> apiKeys,
                    ISafeguardEventHandler handler, String networkAddress, String certificatePath,
                    char[] certificatePassword, Integer apiVersion, Boolean ignoreSsl)
                    throws ObjectDisposedException, ArgumentException {
                
                int version = DEFAULTAPIVERSION;
                if (apiVersion != null) {
                    version = apiVersion;
                }

                boolean sslIgnore = false;
                if (ignoreSsl != null) {
                    sslIgnore = ignoreSsl;
                }

                return new PersistentSafeguardA2AEventListener(
                        new SafeguardA2AContext(networkAddress, certificatePath, certificatePassword, version,
                                ignoreSsl, null), apiKeys, handler);
            }
            
            /**
             *  Get a persistent A2A event listener. The handler passed in 
             *  will be registered for the AssetAccountPasswordUpdated event, 
             *  which is the only one supported in A2A. Uses a client 
             *  certificate from the Windows certificate store. This is a 
             *  Windows only API and requires that the SunMSCAPI security 
             *  provider is available in the Java environment.
             *
             *  @param apiKeys A list of API key corresponding to the configured accounts to
             *  listen for.
             *  @param handler A delegate to call any time the
             *  AssetAccountPasswordUpdate event occurs.
             *  @param networkAddress Network address of Safeguard appliance.
             *  @param thumbprint Thumbprint of the client certificate.
             *  @param apiVersion Target API version to use.
             *  @param validationCallback Callback function to be executed during SSL certificate validation.
             * 
             *  @return New persistent A2A event listener.
             *  @throws ObjectDisposedException Object has already been disposed.
             *  @throws ArgumentException Invalid argument.
             *  @throws SafeguardForJavaException General Safeguard for Java exception.
             */
            public static ISafeguardEventListener getPersistentA2AEventListener(List<char[]> apiKeys,
                    ISafeguardEventHandler handler, String networkAddress, String thumbprint,
                    HostnameVerifier validationCallback, Integer apiVersion)
                    throws ObjectDisposedException, ArgumentException, SafeguardForJavaException {
                
                int version = DEFAULTAPIVERSION;
                if (apiVersion != null) {
                    version = apiVersion;
                }

                if (Utils.isWindows()) {
                    if (!Utils.isSunMSCAPILoaded()) {
                        throw new SafeguardForJavaException("Missing SunMSCAPI provider. The SunMSCAPI provider must be added as a security provider in $JAVA_HOME/jre/lib/security/java.security configuration file.");
                    }
                }
                else {
                    throw new SafeguardForJavaException("Not implemented. This function is only available on the Windows platform.");
                }
                
                return new PersistentSafeguardA2AEventListener(
                        new SafeguardA2AContext(networkAddress, version, false, 
                                thumbprint, validationCallback), apiKeys, handler);
            }
            
            /**
             *  Get a persistent A2A event listener. The handler passed in 
             *  will be registered for the AssetAccountPasswordUpdated event, 
             *  which is the only one supported in A2A. Uses a client 
             *  certificate from the Windows certificate store. This is a 
             *  Windows only API and requires that the SunMSCAPI security 
             *  provider is available in the Java environment.
             *
             *  @param apiKeys A list of API key corresponding to the configured accounts to
             *  listen for.
             *  @param handler A delegate to call any time the
             *  AssetAccountPasswordUpdate event occurs.
             *  @param networkAddress Network address of Safeguard appliance.
             *  @param thumbprint Thumbprint of the client certificate.
             *  @param apiVersion Target API version to use.
             *  @param ignoreSsl Ignore server certificate validation.
             * 
             *  @return New persistent A2A event listener.
             *  @throws ObjectDisposedException Object has already been disposed.
             *  @throws ArgumentException Invalid argument.
             *  @throws SafeguardForJavaException General Safeguard for Java exception.
             */
            public static ISafeguardEventListener getPersistentA2AEventListener(List<char[]> apiKeys,
                    ISafeguardEventHandler handler, String networkAddress, String thumbprint,
                    Integer apiVersion, Boolean ignoreSsl)
                    throws ObjectDisposedException, ArgumentException, SafeguardForJavaException {
                
                int version = DEFAULTAPIVERSION;
                if (apiVersion != null) {
                    version = apiVersion;
                }

                boolean sslIgnore = false;
                if (ignoreSsl != null) {
                    sslIgnore = ignoreSsl;
                }

                if (Utils.isWindows()) {
                    if (!Utils.isSunMSCAPILoaded()) {
                        throw new SafeguardForJavaException("Missing SunMSCAPI provider. The SunMSCAPI provider must be added as a security provider in $JAVA_HOME/jre/lib/security/java.security configuration file.");
                    }
                }
                else {
                    throw new SafeguardForJavaException("Not implemented. This function is only available on the Windows platform.");
                }
        
                return new PersistentSafeguardA2AEventListener(
                        new SafeguardA2AContext(networkAddress, version, ignoreSsl, 
                                thumbprint, null), apiKeys, handler);
            }
            
            /**
             *  Get a persistent A2A event listener. The handler passed in 
             *  will be registered for the AssetAccountPasswordUpdated event, 
             *  which is the only one supported in A2A. Uses a client 
             *  certificate stored in a file.
             *
             *  @param apiKeys A list of API key corresponding to the configured accounts to
             *  listen for.
             *  @param handler A delegate to call any time the
             *  AssetAccountPasswordUpdate event occurs.
             *  @param networkAddress Network address of Safeguard appliance.
             *  @param certificatePath Path to PFX (or PKCS12) certificate file
             *  also containing private key.
             *  @param certificatePassword Password to decrypt the certificate file.
             *  @param apiVersion Target API version to use.
             *  @param validationCallback Callback function to be executed during SSL certificate validation.
             * 
             *  @return New persistent A2A event listener.
             *  @throws ObjectDisposedException Object has already been disposed.
             *  @throws ArgumentException Invalid argument.
             */
            public static ISafeguardEventListener getPersistentA2AEventListener(List<char[]> apiKeys,
                    ISafeguardEventHandler handler, String networkAddress, String certificatePath,
                    char[] certificatePassword, HostnameVerifier validationCallback, Integer apiVersion)
                    throws ObjectDisposedException, ArgumentException {
                
                int version = DEFAULTAPIVERSION;
                if (apiVersion != null) {
                    version = apiVersion;
                }

                return new PersistentSafeguardA2AEventListener(
                        new SafeguardA2AContext(networkAddress, certificatePath, certificatePassword, version,
                                false, validationCallback), apiKeys, handler);
            }
            
            /**
             *  Get a persistent A2A event listener. The handler passed in 
             *  will be registered for the AssetAccountPasswordUpdated event, 
             *  which is the only one supported in A2A. Uses a client 
             *  certificate stored in memory.
             *
             *  @param apiKeys A list of API key corresponding to the configured accounts to
             *  listen for.
             *  @param handler A delegate to call any time the
             *  AssetAccountPasswordUpdate event occurs.
             *  @param networkAddress Network address of Safeguard appliance.
             *  @param certificateData Bytes containing a PFX (or PKCS12) formatted certificate and private key.
             *  @param certificatePassword Password to decrypt the certificate file.
             *  @param apiVersion Target API version to use.
             *  @param ignoreSsl Ignore server certificate validation.
             * 
             *  @return New persistent A2A event listener.
             *  @throws ObjectDisposedException Object has already been disposed.
             *  @throws ArgumentException Invalid argument.
             */
            public static ISafeguardEventListener getPersistentA2AEventListener(List<char[]> apiKeys,
                    ISafeguardEventHandler handler, String networkAddress, byte[] certificateData,
                    char[] certificatePassword, Integer apiVersion, Boolean ignoreSsl)
                    throws ObjectDisposedException, ArgumentException {
                
                int version = DEFAULTAPIVERSION;
                if (apiVersion != null) {
                    version = apiVersion;
                }

                boolean sslIgnore = false;
                if (ignoreSsl != null) {
                    sslIgnore = ignoreSsl;
                }

                return new PersistentSafeguardA2AEventListener(
                        new SafeguardA2AContext(networkAddress, certificateData, certificatePassword, version,
                                ignoreSsl, null), apiKeys, handler);
            }
            
            /**
             *  Get a persistent A2A event listener. The handler passed in 
             *  will be registered for the AssetAccountPasswordUpdated event, 
             *  which is the only one supported in A2A. Uses a client 
             *  certificate stored in memory.
             *
             *  @param apiKeys A list of API key corresponding to the configured accounts to
             *  listen for.
             *  @param handler A delegate to call any time the
             *  AssetAccountPasswordUpdate event occurs.
             *  @param networkAddress Network address of Safeguard appliance.
             *  @param certificateData Bytes containing a PFX (or PKCS12) formatted certificate and private key.
             *  @param certificatePassword Password to decrypt the certificate file.
             *  @param apiVersion Target API version to use.
             *  @param validationCallback Callback function to be executed during SSL certificate validation.
             * 
             *  @return New persistent A2A event listener.
             *  @throws ObjectDisposedException Object has already been disposed.
             *  @throws ArgumentException Invalid argument.
             */
            public static ISafeguardEventListener getPersistentA2AEventListener(List<char[]> apiKeys,
                    ISafeguardEventHandler handler, String networkAddress, byte[] certificateData,
                    char[] certificatePassword, HostnameVerifier validationCallback, Integer apiVersion)
                    throws ObjectDisposedException, ArgumentException {
                
                int version = DEFAULTAPIVERSION;
                if (apiVersion != null) {
                    version = apiVersion;
                }

                return new PersistentSafeguardA2AEventListener(
                        new SafeguardA2AContext(networkAddress, certificateData, certificatePassword, version,
                                false, validationCallback), apiKeys, handler);
            }
        }
    }
}

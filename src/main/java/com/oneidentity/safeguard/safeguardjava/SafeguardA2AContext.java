package com.oneidentity.safeguard.safeguardjava;

import com.oneidentity.safeguard.safeguardjava.exceptions.ObjectDisposedException;
import com.oneidentity.safeguard.safeguardjava.exceptions.SafeguardForJavaException;
import com.oneidentity.safeguard.safeguardjava.restclient.RestClient;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import javax.ws.rs.core.Response;

public class SafeguardA2AContext implements ISafeguardA2AContext
{
    private boolean disposed;

    private final String networkAddress;
    private final boolean ignoreSsl;

    private final X509Certificate clientCertificate;
    private final String certificatePath;
    private final char[] certificatePassword;
    private final RestClient a2AClient;

    private SafeguardA2AContext(String networkAddress, String certificateThumbprint, String certificatePath,
        char[] certificatePassword, int apiVersion, boolean ignoreSsl)
    {
        this.networkAddress = networkAddress;
        String safeguardA2AUrl = String.format("https://%s/service/a2a/v%d", this.networkAddress, apiVersion);
        this.a2AClient = new RestClient(safeguardA2AUrl, ignoreSsl);
        
        this.certificatePath = certificatePath;
        if (certificatePassword != null )
            this.certificatePassword = certificatePassword.clone();
        else
            this.certificatePassword = null;
        
        this.clientCertificate = null;
        this.ignoreSsl = ignoreSsl;
        
//        clientCertificate = !StringUtils.isNullOrEmpty(certificateThumbprint)
//            ? CertificateUtilities.GetClientCertificateFromStore(certificateThumbprint)
//            : CertificateUtilities.GetClientCertificateFromFile(certificatePath, certificatePassword);
//        a2AClient.ClientCertificates = new X509Certificate2Collection() { clientCertificate };
    }

    public SafeguardA2AContext(String networkAddress, String certificateThumbprint, int apiVersion, boolean ignoreSsl) 
    {
        this(networkAddress, certificateThumbprint, null, null, apiVersion, ignoreSsl);
    }

    public SafeguardA2AContext(String networkAddress, String certificatePath, char[] certificatePassword,
        int apiVersion, boolean ignoreSsl)
    {
        this(networkAddress, null, certificatePath, certificatePassword, apiVersion, ignoreSsl);
    }

    public char[] retrievePassword(char[] apiKey) throws ObjectDisposedException, SafeguardForJavaException
    {
        if (disposed)
            throw new ObjectDisposedException("SafeguardA2AContext");

        Map<String,String> headers = new HashMap<>();
        headers.put("Authorization", String.format("A2A %s", new String(apiKey)));
        
        Map<String,String> parameters = new HashMap<>();
        parameters.put("type", "Password");
        
        Response response = a2AClient.execGET("Credentials", parameters, headers, certificatePath, certificatePassword);
        
        if (response == null)
            throw new SafeguardForJavaException(String.format("Unable to connect to web service %s", a2AClient.getBaseURL()));
        if (response.getStatus() != 200)
            throw new SafeguardForJavaException("Error returned from Safeguard API, Error: " +
                    String.format("%s %s", response.getStatus(), response.readEntity(String.class)));
        
        char[] password = response.readEntity(String.class).replaceAll("\"", "").toCharArray();
        return password;
    }

//    private ISafeguardEventListener getEventListenerInternal(SecureString apiKey)
//    {
//        var eventListener = new SafeguardEventListener($"https://{networkAddress}/service/a2a", clientCertificate,
//            apiKey, ignoreSsl);
//        return eventListener;
//    }

//    public ISafeguardEventListener getEventListener(SecureString apiKey, SafeguardEventHandler handler)
//    {
//        if (disposed)
//            throw new ObjectDisposedException("SafeguardA2AContext");
//        var eventListener = GetEventListenerInternal(apiKey);
//        eventListener.RegisterEventHandler("AssetAccountPasswordUpdated", handler);
//        return eventListener;
//    }

//    public ISafeguardEventListener getEventListener(SecureString apiKey, SafeguardParsedEventHandler handler)
//    {
//        if (disposed)
//            throw new ObjectDisposedException("SafeguardA2AContext");
//        var eventListener = GetEventListenerInternal(apiKey);
//        eventListener.RegisterEventHandler("AssetAccountPasswordUpdated", handler);
//        return eventListener;
//    }

    public void dispose()
    {
        if (certificatePassword != null)
            Arrays.fill(certificatePassword, '0');
        disposed = true;
    }
    
    protected void finalize() throws Throwable {
        try {
        if (certificatePassword != null)
            Arrays.fill(certificatePassword, '0');
        } finally {
            disposed = true;
            super.finalize();
        }
    }
    
}

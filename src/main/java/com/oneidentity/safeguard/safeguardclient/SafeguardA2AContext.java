package com.oneidentity.safeguard.safeguardclient;

import com.oneidentity.safeguard.safeguardclient.exceptions.ObjectDisposedException;
import com.oneidentity.safeguard.safeguardclient.exceptions.SafeguardForJavaException;
import com.oneidentity.safeguard.safeguardclient.restclient.RestClient;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import javax.ws.rs.core.Response;

public class SafeguardA2AContext implements ISafeguardA2AContext
{
    private boolean _disposed;

    private final String _networkAddress;
    private final boolean _ignoreSsl;

    private final X509Certificate _clientCertificate;
    private final String _certificatePath;
    private final char[] _certificatePassword;
    private final RestClient _a2AClient;

    private SafeguardA2AContext(String networkAddress, String certificateThumbprint, String certificatePath,
        char[] certificatePassword, int apiVersion, boolean ignoreSsl)
    {
        _networkAddress = networkAddress;
        String safeguardA2AUrl = String.format("https://%s/service/a2a/v%d", _networkAddress, apiVersion);
        _a2AClient = new RestClient(safeguardA2AUrl);
        
        _certificatePath = certificatePath;
        if (certificatePassword != null )
            _certificatePassword = certificatePassword.clone();
        else
            _certificatePassword = null;
        
        _clientCertificate = null;
        _ignoreSsl = ignoreSsl;
//        if (ignoreSsl) {
//            _a2AClient.RemoteCertificateValidationCallback += (sender, certificate, chain, errors) => true;
//        }
//        _clientCertificate = !StringUtils.isNullOrEmpty(certificateThumbprint)
//            ? CertificateUtilities.GetClientCertificateFromStore(certificateThumbprint)
//            : CertificateUtilities.GetClientCertificateFromFile(certificatePath, certificatePassword);
//        _a2AClient.ClientCertificates = new X509Certificate2Collection() { _clientCertificate };
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

    public char[] RetrievePassword(char[] apiKey) throws ObjectDisposedException, SafeguardForJavaException
    {
        if (_disposed)
            throw new ObjectDisposedException("SafeguardA2AContext");

        Map<String,String> headers = new HashMap<>();
        headers.put("Authorization", String.format("A2A %s", new String(apiKey)));
        
        Map<String,String> parameters = new HashMap<>();
        parameters.put("type", "Password");
        
        Response response = _a2AClient.execGET("Credentials", parameters, headers, _certificatePath, _certificatePassword);
        
//        if (response.ResponseStatus != ResponseStatus.Completed)
//            throw new SafeguardDotNetException($"Unable to connect to web service {_a2AClient.BaseUrl}, Error: " +
//                                               response.ErrorMessage);
        if (response.getStatus() != 200)
            throw new SafeguardForJavaException("Error returned from Safeguard API, Error: " +
                    String.format("%s %s", response.getStatus(), response.readEntity(String.class)));
        
        char[] password = response.readEntity(String.class).replaceAll("\"", "").toCharArray();
        return password;
    }

//    private ISafeguardEventListener GetEventListenerInternal(SecureString apiKey)
//    {
//        var eventListener = new SafeguardEventListener($"https://{_networkAddress}/service/a2a", _clientCertificate,
//            apiKey, _ignoreSsl);
//        return eventListener;
//    }

//    public ISafeguardEventListener GetEventListener(SecureString apiKey, SafeguardEventHandler handler)
//    {
//        if (_disposed)
//            throw new ObjectDisposedException("SafeguardA2AContext");
//        var eventListener = GetEventListenerInternal(apiKey);
//        eventListener.RegisterEventHandler("AssetAccountPasswordUpdated", handler);
//        return eventListener;
//    }

//    public ISafeguardEventListener GetEventListener(SecureString apiKey, SafeguardParsedEventHandler handler)
//    {
//        if (_disposed)
//            throw new ObjectDisposedException("SafeguardA2AContext");
//        var eventListener = GetEventListenerInternal(apiKey);
//        eventListener.RegisterEventHandler("AssetAccountPasswordUpdated", handler);
//        return eventListener;
//    }

    public void Dispose()
    {
        if (_certificatePassword != null)
            Arrays.fill(_certificatePassword, '0');
        _disposed = true;
    }
    
    protected void finalize() throws Throwable {
        try {
        if (_certificatePassword != null)
            Arrays.fill(_certificatePassword, '0');
        } finally {
            _disposed = true;
            super.finalize();
        }
    }
    
}

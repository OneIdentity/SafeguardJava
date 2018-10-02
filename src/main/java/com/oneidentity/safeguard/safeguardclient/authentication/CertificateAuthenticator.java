package com.oneidentity.safeguard.safeguardclient.authentication;

import com.oneidentity.safeguard.safeguardclient.StringUtils;
import com.oneidentity.safeguard.safeguardclient.data.OauthBody;
import com.oneidentity.safeguard.safeguardclient.exceptions.ObjectDisposedException;
import com.oneidentity.safeguard.safeguardclient.exceptions.SafeguardForJavaException;
import java.util.Arrays;
import java.util.Map;
import javax.ws.rs.core.Response;

public class CertificateAuthenticator extends AuthenticatorBase
{
    private boolean _disposed;

    private final String certificateThumbprint;
    private final String certificatePath;
    private final char[] certificatePassword;

    public CertificateAuthenticator(String networkAddress, String certificateThumbprint, int apiVersion,
        boolean ignoreSsl)
    {
        super(networkAddress, null, null, apiVersion, ignoreSsl);
        this.certificateThumbprint = certificateThumbprint;
        this.certificatePath = null;
        this.certificatePassword = null;
    }

    public CertificateAuthenticator(String networkAddress, String certificatePath, char[] certificatePassword,
        int apiVersion, boolean ignoreSsl)
    {
        super(networkAddress, certificatePath, certificatePassword, apiVersion, ignoreSsl);
        this.certificatePath = certificatePath;
        this.certificatePassword = certificatePassword.clone();
        this.certificateThumbprint = null;
    }

    @Override
    protected char[] GetRstsTokenInternal() throws ObjectDisposedException, SafeguardForJavaException
    {
        if (_disposed)
            throw new ObjectDisposedException("CertificateAuthenticator");

        OauthBody body = new OauthBody("client_credentials", "rsts:sts:primaryproviderid:certificate");
        Response response = RstsClient.execPOST("oauth2/token", null, null, body, certificatePath, certificatePassword);
        
//        var userCert = !StringUtils.isNullOrEmpty(certificateThumbprint)
//            ? CertificateUtilities.GetClientCertificateFromStore(_certificateThumbprint)
//            : CertificateUtilities.GetClientCertificateFromFile(_certificatePath, _certificatePassword);
//        RstsClient.ClientCertificates = new X509Certificate2Collection() { userCert };

//        if (response.ResponseStatus != ResponseStatus.Completed)
//            throw new SafeguardForJavaException(String.format("Unable to connect to RSTS service %s, Error: ", RstsClient.BaseUrl) +
//                    response.ErrorMessage);
        if (response.getStatus() != 200) {
            String msg = StringUtils.isNullOrEmpty(certificatePath) ? String.format("thumbprint=%s", certificateThumbprint) : String.format("file=%s", certificatePath);
            String content = response.readEntity(String.class);
            throw new SafeguardForJavaException("Error using client_credentials grant_type with " + msg +
                    String.format(", Error: %d %s", response.getStatus(), content));
        }
        
        Map<String,String> map = StringUtils.ParseResponse(response);
        
        String accessToken = map.get("access_token");
        return accessToken.toCharArray();
    }

    @Override
    public void Dispose()
    {
        super.Dispose();
        Arrays.fill(certificatePassword, '0');
        _disposed = true;
    }
    
    @Override
    protected void finalize() throws Throwable {
        try {
            Arrays.fill(certificatePassword, '0');
        } finally {
            _disposed = true;
            super.finalize();
        }
    }
    
}

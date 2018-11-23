package com.oneidentity.safeguard.safeguardjava.authentication;

import com.oneidentity.safeguard.safeguardjava.Utils;
import com.oneidentity.safeguard.safeguardjava.data.OauthBody;
import com.oneidentity.safeguard.safeguardjava.exceptions.ObjectDisposedException;
import com.oneidentity.safeguard.safeguardjava.exceptions.SafeguardForJavaException;
import java.util.Arrays;
import java.util.Map;
import javax.ws.rs.core.Response;

public class CertificateAuthenticator extends AuthenticatorBase
{
    private boolean disposed;

    private final String certificateAlias;
    private final String certificatePath;
    private final char[] certificatePassword;

    public CertificateAuthenticator(String networkAddress, String keystorePath, char[] keystorePassword, String certificateAlias, int apiVersion,
        boolean ignoreSsl)
    {
        super(networkAddress, null, null, apiVersion, ignoreSsl);
        this.certificateAlias = certificateAlias;
        this.certificatePath = keystorePath;
        this.certificatePassword = keystorePassword == null ? null : keystorePassword.clone();
    }

    public CertificateAuthenticator(String networkAddress, String certificatePath, char[] certificatePassword,
        int apiVersion, boolean ignoreSsl)
    {
        super(networkAddress, certificatePath, certificatePassword, apiVersion, ignoreSsl);
        this.certificatePath = certificatePath;
        this.certificatePassword = certificatePassword == null ? null : certificatePassword.clone();
        this.certificateAlias = null;
    }

    @Override
    protected char[] getRstsTokenInternal() throws ObjectDisposedException, SafeguardForJavaException
    {
        if (disposed)
            throw new ObjectDisposedException("CertificateAuthenticator");

        Response response = null;
        OauthBody body = new OauthBody("client_credentials", "rsts:sts:primaryproviderid:certificate");
        
        response = rstsClient.execPOST("oauth2/token", null, null, body, certificatePath, certificatePassword, certificateAlias);
            
        if (response == null)
            throw new SafeguardForJavaException(String.format("Unable to connect to RSTS service %s", rstsClient.getBaseURL()));
        if (!Utils.isSuccessful(response.getStatus())) {
            String msg = Utils.isNullOrEmpty(certificateAlias) ? String.format("file=%s", certificatePath) : String.format("alias=%s", certificateAlias);
            String content = response.readEntity(String.class);
            throw new SafeguardForJavaException("Error using client_credentials grant_type with " + msg +
                    String.format(", Error: %d %s", response.getStatus(), content));
        }
        
        Map<String,String> map = Utils.parseResponse(response);
        
        if (!map.containsKey("access_token")) {
            throw new SafeguardForJavaException(String.format("Error retrieving the access token for certificate: %s", certificatePath));
        }
        
        return map.get("access_token").toCharArray();
    }

    @Override
    public void dispose()
    {
        super.dispose();
        if (certificatePassword != null)
            Arrays.fill(certificatePassword, '0');
        disposed = true;
    }
    
    @Override
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

package com.oneidentity.safeguard.safeguardjava.authentication;

import com.oneidentity.safeguard.safeguardjava.Utils;
import com.oneidentity.safeguard.safeguardjava.data.CertificateContext;
import com.oneidentity.safeguard.safeguardjava.data.OauthBody;
import com.oneidentity.safeguard.safeguardjava.exceptions.ObjectDisposedException;
import com.oneidentity.safeguard.safeguardjava.exceptions.SafeguardForJavaException;
import java.util.Map;
import org.apache.http.client.methods.CloseableHttpResponse;

public class CertificateAuthenticator extends AuthenticatorBase
{
    private boolean disposed;

    private final CertificateContext clientCertificate;

    public CertificateAuthenticator(String networkAddress, String keystorePath, char[] keystorePassword, String certificateAlias, 
            int apiVersion, boolean ignoreSsl)
    {
        super(networkAddress, null, null, apiVersion, ignoreSsl);
        clientCertificate = new CertificateContext(certificateAlias, keystorePath, keystorePassword);
    }

    public CertificateAuthenticator(String networkAddress, String certificatePath, char[] certificatePassword,
            int apiVersion, boolean ignoreSsl) {
        
        super(networkAddress, certificatePath, certificatePassword, apiVersion, ignoreSsl);
        clientCertificate = new CertificateContext(null, certificatePath, certificatePassword);
    }

    private CertificateAuthenticator(String networkAddress, CertificateContext clientCertificate, int apiVersion, boolean ignoreSsl) {
        
        super(networkAddress, clientCertificate.getCertificatePath(), clientCertificate.getCertificatePassword(), apiVersion, ignoreSsl);
        this.clientCertificate = clientCertificate.cloneObject();
    }
    
    @Override
    public String getId() {
        return "Certificate";
    }
    
    @Override
    protected char[] getRstsTokenInternal() throws ObjectDisposedException, SafeguardForJavaException
    {
        if (disposed)
            throw new ObjectDisposedException("CertificateAuthenticator");

        CloseableHttpResponse response = null;
        OauthBody body = new OauthBody("client_credentials", "rsts:sts:primaryproviderid:certificate");
        
        response = rstsClient.execPOST("oauth2/token", null, null, body, clientCertificate.getCertificatePath(), 
                clientCertificate.getCertificatePassword(), clientCertificate.getCertificateAlias());
            
        if (response == null)
            throw new SafeguardForJavaException(String.format("Unable to connect to RSTS service %s", rstsClient.getBaseURL()));
        
        String content = Utils.getResponse(response);
        if (!Utils.isSuccessful(response.getStatusLine().getStatusCode())) {
            String msg = Utils.isNullOrEmpty(clientCertificate.getCertificateAlias()) ? 
                    String.format("file=%s", clientCertificate.getCertificatePath()) : String.format("alias=%s", clientCertificate.getCertificateAlias());
            
            throw new SafeguardForJavaException("Error using client_credentials grant_type with " + clientCertificate.toString() +
                    String.format(", Error: %d %s", response.getStatusLine().getStatusCode(), content));
        }
        
        Map<String,String> map = Utils.parseResponse(content);
        
        if (!map.containsKey("access_token")) {
            throw new SafeguardForJavaException(String.format("Error retrieving the access token for certificate: %s", clientCertificate.getCertificatePath()));
        }
        
        return map.get("access_token").toCharArray();
    }

    @Override
    public Object cloneObject() throws SafeguardForJavaException {
        CertificateAuthenticator auth = new CertificateAuthenticator(this.getNetworkAddress(), clientCertificate, this.getApiVersion(), this.isIgnoreSsl());
        if (this.accessToken != null) {
            auth.accessToken = this.accessToken.clone();
        }
        return auth;
    }
    
    @Override
    public void dispose()
    {
        super.dispose();
        clientCertificate.dispose();
        disposed = true;
    }
    
    @Override
    protected void finalize() throws Throwable {
        try {
            clientCertificate.dispose();
        } finally {
            disposed = true;
            super.finalize();
        }
    }

}

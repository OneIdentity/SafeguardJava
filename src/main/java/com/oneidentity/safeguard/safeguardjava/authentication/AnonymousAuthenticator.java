package com.oneidentity.safeguard.safeguardjava.authentication;

import com.oneidentity.safeguard.safeguardjava.Utils;
import com.oneidentity.safeguard.safeguardjava.exceptions.SafeguardForJavaException;
import com.oneidentity.safeguard.safeguardjava.restclient.RestClient;
import java.util.HashMap;
import java.util.Map;
import javax.net.ssl.HostnameVerifier;
import org.apache.http.HttpHeaders;
import org.apache.http.client.methods.CloseableHttpResponse;

public class AnonymousAuthenticator extends AuthenticatorBase {

    private boolean disposed;

    public AnonymousAuthenticator(String networkAddress, int apiVersion, boolean ignoreSsl, HostnameVerifier validationCallback) throws SafeguardForJavaException {
        super(networkAddress, apiVersion, ignoreSsl, validationCallback);
        
        String notificationUrl = String.format("https://%s/service/notification/v%d", networkAddress, apiVersion);
        RestClient notificationClient = new RestClient(notificationUrl, ignoreSsl, validationCallback);
        
        Map<String,String> headers = new HashMap<>();
        headers.put(HttpHeaders.ACCEPT, "application/json");
        headers.put(HttpHeaders.CONTENT_TYPE, "application/json");
        CloseableHttpResponse response = notificationClient.execGET("Status", null, headers, null);

        if (response == null) {
            throw new SafeguardForJavaException(String.format("Unable to anonymously connect to web service %s", notificationClient.getBaseURL()));
        }
        
        String reply = Utils.getResponse(response);

        if (!Utils.isSuccessful(response.getStatusLine().getStatusCode())) {
            throw new SafeguardForJavaException("Unable to anonymously connect to {networkAddress}, Error: "
                    + String.format("%d %s", response.getStatusLine().getStatusCode(), reply));
        }
    }

    @Override
    public String getId() {
        return "Anonymous";
    }
    
    @Override
    public boolean isAnonymous() {
        return true;
    }
    
    @Override
    protected char[] getRstsTokenInternal() throws SafeguardForJavaException {
        throw new SafeguardForJavaException("Anonymous connection cannot be used to get an API access token, Error: Unsupported operation");
    }

    @Override
    public boolean hasAccessToken() {
        return true;
    }
    
    @Override
    public Object cloneObject() throws SafeguardForJavaException {
        throw new SafeguardForJavaException("Anonymous authenticators are not cloneable");
    }
    
    @Override
    public void dispose() {
        super.dispose();
        disposed = true;
    }

    @Override
    protected void finalize() throws Throwable {
        try {
        } finally {
            disposed = true;
            super.finalize();
        }
    }

}

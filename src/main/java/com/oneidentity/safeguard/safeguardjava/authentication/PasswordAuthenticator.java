package com.oneidentity.safeguard.safeguardjava.authentication;

import com.oneidentity.safeguard.safeguardjava.Utils;
import com.oneidentity.safeguard.safeguardjava.data.OauthBody;
import com.oneidentity.safeguard.safeguardjava.exceptions.ArgumentException;
import com.oneidentity.safeguard.safeguardjava.exceptions.ObjectDisposedException;
import com.oneidentity.safeguard.safeguardjava.exceptions.SafeguardForJavaException;
import java.util.Arrays;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.HostnameVerifier;
import org.apache.http.client.methods.CloseableHttpResponse;

public class PasswordAuthenticator extends AuthenticatorBase 
{
    private boolean disposed;

    private final String provider;
    private String providerScope;
    private final String username;
    private final char[] password;

    public PasswordAuthenticator(String networkAddress, String provider, String username,
            char[] password, int apiVersion, boolean ignoreSsl, HostnameVerifier validationCallback) 
            throws ArgumentException
    {
        super(networkAddress, apiVersion, ignoreSsl, validationCallback);
        this.provider = provider;
        
        if (Utils.isNullOrEmpty(this.provider) || this.provider.equalsIgnoreCase("local"))
            providerScope = "rsts:sts:primaryproviderid:local";
        
        this.username = username;
        if (password == null)
            throw new ArgumentException("The password parameter can not be null");
        this.password = password.clone();
    }

    @Override
    public String getId() {
        return "Password";
    }

    @Override
    protected char[] getRstsTokenInternal() throws ObjectDisposedException, SafeguardForJavaException
    {
        if (disposed)
            throw new ObjectDisposedException("PasswordAuthenticator");
        if (providerScope == null)
            providerScope = resolveProviderToScope(provider);

        OauthBody body = new OauthBody("password", username, password, providerScope);
        CloseableHttpResponse response = rstsClient.execPOST("oauth2/token", null, null, body);

        if (response == null)
            throw new SafeguardForJavaException(String.format("Unable to connect to RSTS service %s", rstsClient.getBaseURL()));
        
        String reply = Utils.getResponse(response);
        if (!Utils.isSuccessful(response.getStatusLine().getStatusCode())) 
            throw new SafeguardForJavaException(String.format("Error using password grant_type with scope %s, Error: ", providerScope) +
                    String.format("%s %s", response.getStatusLine().getStatusCode(), reply));

        Map<String,String> map = Utils.parseResponse(reply);

        if (!map.containsKey("access_token"))
            throw new SafeguardForJavaException(String.format("Error retrieving the access key for scope: %s", providerScope));
        
        return map.get("access_token").toCharArray();
    }

    @Override
    public Object cloneObject() throws SafeguardForJavaException
    {
        try {
            PasswordAuthenticator auth = new PasswordAuthenticator(getNetworkAddress(), provider, username, password, 
                    getApiVersion(), isIgnoreSsl(), getValidationCallback());
            auth.accessToken = this.accessToken == null ? null : this.accessToken.clone();
            return auth;
        } catch (ArgumentException ex) {
            Logger.getLogger(PasswordAuthenticator.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }
    
    @Override
    public void dispose()
    {
        super.dispose();
        if (password != null)
            Arrays.fill(password, '0');
        disposed = true;
    }
    
    @Override
    protected void finalize() throws Throwable {
        try {
            if (password != null)
                Arrays.fill(password, '0');
        } finally {
            disposed = true;
            super.finalize();
        }
    }
    
}

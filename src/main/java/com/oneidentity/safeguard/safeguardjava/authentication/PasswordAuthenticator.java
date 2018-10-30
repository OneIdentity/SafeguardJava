package com.oneidentity.safeguard.safeguardjava.authentication;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.oneidentity.safeguard.safeguardjava.StringUtils;
import com.oneidentity.safeguard.safeguardjava.data.OauthBody;
import com.oneidentity.safeguard.safeguardjava.exceptions.ObjectDisposedException;
import com.oneidentity.safeguard.safeguardjava.exceptions.SafeguardForJavaException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.ws.rs.core.Response;

public class PasswordAuthenticator extends AuthenticatorBase 
{
    private boolean disposed;

    private final String provider;
    private String providerScope;
    private final String username;
    private final char[] password;

    public PasswordAuthenticator(String networkAddress, String provider, String username,
        char[] password, int apiVersion, boolean ignoreSsl)
    {
        super(networkAddress, null, null, apiVersion, ignoreSsl);
        this.provider = provider;
        
        if (StringUtils.isNullOrEmpty(this.provider) || this.provider.equalsIgnoreCase("local"))
            providerScope = "rsts:sts:primaryproviderid:local";
        
        this.username = username;
        this.password = password;
    }

    private void resolveProviderToScope() throws SafeguardForJavaException
    {
        try
        {
            Response response;
            Map<String,String> headers = new HashMap<>();
            Map<String,String> parameters = new HashMap<>();
            
            headers.clear();
            parameters.clear();

            headers.put("Content-type", "application/x-www-form-urlencoded");
            parameters.put("response_type", "token");
            parameters.put("redirect_uri", "urn:InstalledApplication");
            parameters.put("loginRequestStep", "1");

            response = rstsClient.execPOST("UserLogin/LoginController", parameters, headers, "RelayState=");
                
            if (response == null || response.getStatus() != 200)
                response = rstsClient.execGET("UserLogin/LoginController", parameters, headers);
            
            if (response == null)
                throw new SafeguardForJavaException("Unable to connect to RSTS to find identity provider scopes");
            if (response.getStatus() != 200)
                throw new SafeguardForJavaException("Error requesting identity provider scopes from RSTS, Error: " +
                        String.format("%d %s", response.getStatus(), response.readEntity(String.class)));

            List<String> knownScopes = parseLoginResponse(response);
            String scope = getMatchingScope(knownScopes, true);

            if (scope != null)
                providerScope = String.format("rsts:sts:primaryproviderid:%s", scope);
            else
            {
                scope = getMatchingScope(knownScopes, false);
                if (providerScope != null)
                    providerScope = String.format("rsts:sts:primaryproviderid:%s", scope);
                else
                    throw new SafeguardForJavaException(String.format("Unable to find scope matching '%s' in [%s]", provider, String.join(",", knownScopes)));
            }
        }
        catch (Exception ex)
        {
            throw new SafeguardForJavaException("Unable to connect to determine identity provider", ex);
        }
    }

    @Override
    protected char[] getRstsTokenInternal() throws ObjectDisposedException, SafeguardForJavaException
    {
        if (disposed)
            throw new ObjectDisposedException("PasswordAuthenticator");
        if (providerScope == null)
            resolveProviderToScope();

        OauthBody body = new OauthBody("password", username, password, providerScope);
        Response response = rstsClient.execPOST("oauth2/token", null, null, body);

        if (response == null)
            throw new SafeguardForJavaException(String.format("Unable to connect to RSTS service %s", rstsClient.getBaseURL()));
        if (response.getStatus() != 200)
            throw new SafeguardForJavaException(String.format("Error using password grant_type with scope %s, Error: ", providerScope) +
                    String.format("%s %s", response.getStatus(), response.readEntity(String.class)));

        Map<String,String> map = StringUtils.parseResponse(response);

        if (!map.containsKey("access_token"))
            throw new SafeguardForJavaException(String.format("Error retrieving the access key for scope: %s", providerScope));
        
        return map.get("access_token").toCharArray();
    }

    @Override
    public void dispose()
    {
        super.dispose();
        Arrays.fill(password, '0');
        disposed = true;
    }
    
    @Override
    protected void finalize() throws Throwable {
        try {
            Arrays.fill(password, '0');
        } finally {
            disposed = true;
            super.finalize();
        }
    }
    
    private List<String> parseLoginResponse(Response response) {
        
        List<String> providers = new ArrayList<String>();
        ObjectMapper mapper = new ObjectMapper();
        
        try {
            JsonNode jsonNodeRoot = mapper.readTree(response.readEntity(String.class));
            JsonNode jsonNodeProviders = jsonNodeRoot.get("Providers");
            Iterator<JsonNode> iter = jsonNodeProviders.elements();
            
            while(iter.hasNext()){
		JsonNode providerNode=iter.next();
		providers.add(getJsonValue(providerNode, "Id"));
            }            
        } catch (IOException ex) {
            Logger.getLogger(StringUtils.class.getName()).log(Level.SEVERE, null, ex);
        }

        return providers;
    }
    
    private String getMatchingScope(List<String> providers, boolean equals) {
        for (String s : providers) {
            if (equals) {
                if (s.equalsIgnoreCase(provider))
                    return s;
            } else {
                if (s.toLowerCase().contains(provider.toLowerCase()))
                    return s;
            }
        }
        return null;
    }
    
    private String getJsonValue(JsonNode node, String propName) {
        if (node.get(propName) != null) {
            return node.get(propName).asText();
        }
        return null;
    }
    
    
}

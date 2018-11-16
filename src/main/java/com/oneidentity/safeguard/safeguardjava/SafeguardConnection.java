package com.oneidentity.safeguard.safeguardjava;

import com.oneidentity.safeguard.safeguardjava.authentication.AnonymousAuthenticator;
import com.oneidentity.safeguard.safeguardjava.authentication.IAuthenticationMechanism;
import com.oneidentity.safeguard.safeguardjava.data.FullResponse;
import com.oneidentity.safeguard.safeguardjava.data.JsonBody;
import com.oneidentity.safeguard.safeguardjava.data.Method;
import com.oneidentity.safeguard.safeguardjava.data.Service;
import com.oneidentity.safeguard.safeguardjava.event.ISafeguardEventListener;
import com.oneidentity.safeguard.safeguardjava.event.SafeguardEventListener;
import com.oneidentity.safeguard.safeguardjava.exceptions.ObjectDisposedException;
import com.oneidentity.safeguard.safeguardjava.exceptions.SafeguardForJavaException;
import com.oneidentity.safeguard.safeguardjava.restclient.RestClient;
import java.util.HashMap;
import java.util.Map;
import javax.ws.rs.core.Response;

class SafeguardConnection implements ISafeguardConnection {

    private boolean disposed;

    private final IAuthenticationMechanism authenticationMechanism;

    private final RestClient coreClient;
    private final RestClient applianceClient;
    private final RestClient notificationClient;

    public SafeguardConnection(IAuthenticationMechanism authenticationMechanism) {
        this.authenticationMechanism = authenticationMechanism;

        String safeguardCoreUrl = String.format("https://%s/service/core/v%d",
                this.authenticationMechanism.getNetworkAddress(), this.authenticationMechanism.getApiVersion());
        coreClient = new RestClient(safeguardCoreUrl, authenticationMechanism.isIgnoreSsl());

        String safeguardApplianceUrl = String.format("https://%s/service/appliance/v%d",
                this.authenticationMechanism.getNetworkAddress(), this.authenticationMechanism.getApiVersion());
        applianceClient = new RestClient(safeguardApplianceUrl, authenticationMechanism.isIgnoreSsl());

        String safeguardNotificationUrl = String.format("https://%s/service/notification/v%d",
                this.authenticationMechanism.getNetworkAddress(), this.authenticationMechanism.getApiVersion());
        notificationClient = new RestClient(safeguardNotificationUrl, authenticationMechanism.isIgnoreSsl());
    }

    @Override
    public int getAccessTokenLifetimeRemaining() throws ObjectDisposedException, SafeguardForJavaException {
        if (disposed) {
            throw new ObjectDisposedException("SafeguardConnection");
        }
        return authenticationMechanism.getAccessTokenLifetimeRemaining();
    }

    @Override
    public void refreshAccessToken() throws ObjectDisposedException, SafeguardForJavaException {
        if (disposed) {
            throw new ObjectDisposedException("SafeguardConnection");
        }
        authenticationMechanism.refreshAccessToken();
    }

    @Override
    public String invokeMethod(Service service, Method method, String relativeUrl, String body,
            Map<String, String> parameters, Map<String, String> additionalHeaders)
            throws ObjectDisposedException, SafeguardForJavaException {
        if (disposed) {
            throw new ObjectDisposedException("SafeguardConnection");
        }
        return invokeMethodFull(service, method, relativeUrl, body, parameters, additionalHeaders).getBody();
    }

    @Override
    public FullResponse invokeMethodFull(Service service, Method method, String relativeUrl,
            String body, Map<String, String> parameters, Map<String, String> additionalHeaders)
            throws ObjectDisposedException, SafeguardForJavaException {

        if (disposed) {
            throw new ObjectDisposedException("SafeguardConnection");
        }
        
        RestClient client = getClientForService(service);
        
        Map<String,String> headers = prepareHeaders(additionalHeaders, service);
        Response response = null;
        
        switch (method) {
            case Get:
                response = client.execGET(relativeUrl, parameters, headers);
                break;
            case Post:
                response = client.execPOST(relativeUrl, parameters, headers, new JsonBody(body));
                break;
            case Put:
                response = client.execPUT(relativeUrl, parameters, headers, new JsonBody(body));
                break;
            case Delete:
                response = client.execDELETE(relativeUrl, parameters, headers);
                break;
        }
        
        if (response == null) {
            throw new SafeguardForJavaException(String.format("Unable to connect to web service %s", client.getBaseURL()));
        }
        if (!Utils.isSuccessful(response.getStatus())) {
            String reply = response.readEntity(String.class);
            throw new SafeguardForJavaException("Error returned from Safeguard API, Error: "
                    + String.format("%d %s", response.getStatus(), reply));
        }
            
        FullResponse fullResponse = new FullResponse(response.getStatus(), response.getHeaders(), response.readEntity(String.class));
        return fullResponse;
    }

    @Override
    public SafeguardEventListener getEventListener() throws ObjectDisposedException {
        SafeguardEventListener eventListener = new SafeguardEventListener(
                String.format("https://%s/service/event", authenticationMechanism.getNetworkAddress()),
                authenticationMechanism.getAccessToken(), authenticationMechanism.isIgnoreSsl());
        return eventListener;
    }

    private RestClient getClientForService(Service service) throws SafeguardForJavaException {
        switch (service) {
            case Core:
                return coreClient;
            case Appliance:
                return applianceClient;
            case Notification:
                return notificationClient;
            case A2A:
                throw new SafeguardForJavaException(
                        "You must call the A2A service using the A2A specific method, Error: Unsupported operation");
            default:
                throw new SafeguardForJavaException("Unknown or unsupported service specified");
        }
    }
    
    private Map<String,String> prepareHeaders(Map<String,String> additionalHeaders, Service service) 
            throws ObjectDisposedException {
        
        Map<String,String> headers = new HashMap<>();
        if (!(authenticationMechanism instanceof AnonymousAuthenticator)) { 
            headers.put("Authorization", String.format("Bearer %s", new String(authenticationMechanism.getAccessToken())));
        }
        
        if (additionalHeaders != null) 
            headers.putAll(additionalHeaders);
        
        return headers;
    }

    @Override
    public void dispose()
    {
        if (authenticationMechanism != null)
            authenticationMechanism.dispose();
        disposed = true;
    }

    @Override
    protected void finalize() throws Throwable {
        try {
            if (authenticationMechanism != null)
                authenticationMechanism.dispose();
        } finally {
            disposed = true;
            super.finalize();
        }
    }
}

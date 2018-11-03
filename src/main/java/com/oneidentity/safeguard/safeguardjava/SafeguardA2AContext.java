package com.oneidentity.safeguard.safeguardjava;

import com.oneidentity.safeguard.safeguardjava.data.BrokeredAccessRequest;
import com.oneidentity.safeguard.safeguardjava.event.ISafeguardEventListener;
import com.oneidentity.safeguard.safeguardjava.event.PersistentSafeguardEventListenerBase;
import com.oneidentity.safeguard.safeguardjava.event.SafeguardEventHandler;
import com.oneidentity.safeguard.safeguardjava.event.SafeguardEventListener;
import com.oneidentity.safeguard.safeguardjava.exceptions.ArgumentException;
import com.oneidentity.safeguard.safeguardjava.exceptions.ObjectDisposedException;
import com.oneidentity.safeguard.safeguardjava.exceptions.SafeguardForJavaException;
import com.oneidentity.safeguard.safeguardjava.restclient.RestClient;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.ws.rs.core.Response;

public class SafeguardA2AContext implements ISafeguardA2AContext {

    private boolean disposed;

    private final String networkAddress;
    private final boolean ignoreSsl;

    private final X509Certificate clientCertificate;
    private final String certificateAlias;
    private final String certificatePath;
    private final char[] certificatePassword;
    private final RestClient a2AClient;

    public SafeguardA2AContext(String networkAddress, String certificateAlias, String certificatePath,
            char[] certificatePassword, int apiVersion, boolean ignoreSsl) {
        this.networkAddress = networkAddress;
        String safeguardA2AUrl = String.format("https://%s/service/a2a/v%d", this.networkAddress, apiVersion);
        this.a2AClient = new RestClient(safeguardA2AUrl, ignoreSsl);

        this.certificateAlias = certificateAlias;
        this.certificatePath = certificatePath;
        if (certificatePassword != null) {
            this.certificatePassword = certificatePassword.clone();
        } else {
            this.certificatePassword = null;
        }

        this.clientCertificate = null;
        this.ignoreSsl = ignoreSsl;
    }

    public SafeguardA2AContext(String networkAddress, String certificatePath, char[] certificatePassword,
            int apiVersion, boolean ignoreSsl) {
        this(networkAddress, null, certificatePath, certificatePassword, apiVersion, ignoreSsl);
    }

    @Override
    public char[] retrievePassword(char[] apiKey) throws ObjectDisposedException, SafeguardForJavaException {
        if (disposed) {
            throw new ObjectDisposedException("SafeguardA2AContext");
        }

        Map<String, String> headers = new HashMap<>();
        headers.put("Authorization", String.format("A2A %s", new String(apiKey)));

        Map<String, String> parameters = new HashMap<>();
        parameters.put("type", "Password");

        Response response = a2AClient.execGET("Credentials", parameters, headers, certificatePath, certificatePassword);

        if (response == null) {
            throw new SafeguardForJavaException(String.format("Unable to connect to web service %s", a2AClient.getBaseURL()));
        }
        if (!Utils.isSuccessful(response.getStatus())) {
            throw new SafeguardForJavaException("Error returned from Safeguard API, Error: "
                    + String.format("%s %s", response.getStatus(), response.readEntity(String.class)));
        }

        char[] password = response.readEntity(String.class).replaceAll("\"", "").toCharArray();
        return password;
    }

    @Override
    public ISafeguardEventListener getEventListener(char[] apiKey, SafeguardEventHandler handler)
            throws ObjectDisposedException, ArgumentException {
        
        if (disposed) {
            throw new ObjectDisposedException("SafeguardA2AContext");
        }
        if (apiKey == null) {
            throw new ArgumentException("The apiKey parameter may not be null");
        }

        SafeguardEventListener eventListener = new SafeguardEventListener(String.format("https://%s/service/a2a", networkAddress),
                clientCertificate, apiKey, ignoreSsl);
        eventListener.registerEventHandler("AssetAccountPasswordUpdated", handler);
        Logger.getLogger(SafeguardA2AContext.class.getName()).log(Level.INFO, "Event listener successfully created for Safeguard A2A context.");
        return eventListener;
    }

    @Override
    public String BrokerAccessRequest(char[] apiKey, BrokeredAccessRequest accessRequest)
            throws ObjectDisposedException, SafeguardForJavaException, ArgumentException {

        if (disposed) {
            throw new ObjectDisposedException("SafeguardA2AContext");
        }
        if (apiKey == null) {
            throw new ArgumentException("apiKey parameter may not be null");
        }
        if (accessRequest == null) {
            throw new ArgumentException("accessRequest parameter may not be null");
        }
        if (accessRequest.getForUserId() == null && accessRequest.getForUserName() == null) {
            throw new SafeguardForJavaException("You must specify a user to create an access request for");
        }
        if (accessRequest.getAssetId() == null && accessRequest.getAssetName() == null) {
            throw new SafeguardForJavaException("You must specify an asset to create an access request for");
        }

        Map<String, String> headers = new HashMap<>();
        headers.put("Accept", "application/json");
        headers.put("Authorization", String.format("A2A %s", new String(apiKey)));

        Map<String, String> parameters = new HashMap<>();

        Response response = a2AClient.execPOST("AccessRequests", parameters, headers, accessRequest, certificatePath, certificatePassword, certificateAlias);

        if (response == null) {
            throw new SafeguardForJavaException(String.format("Unable to connect to web service %s", a2AClient.getBaseURL()));
        }
        if (response.getStatus() != 200) {
            throw new SafeguardForJavaException("Error returned from Safeguard API, Error: "
                    + String.format("%s %s", response.getStatus(), response.readEntity(String.class)));
        }

        return response.readEntity(String.class);
    }

    @Override
    public void dispose() {
        if (certificatePassword != null) {
            Arrays.fill(certificatePassword, '0');
        }
        disposed = true;
    }

    @Override
    protected void finalize() throws Throwable {
        try {
            if (certificatePassword != null) {
                Arrays.fill(certificatePassword, '0');
            }
        } finally {
            disposed = true;
            super.finalize();
        }
    }

}

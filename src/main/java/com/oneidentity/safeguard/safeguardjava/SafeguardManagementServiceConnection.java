package com.oneidentity.safeguard.safeguardjava;

import com.oneidentity.safeguard.safeguardjava.authentication.IAuthenticationMechanism;
import com.oneidentity.safeguard.safeguardjava.authentication.ManagementServiceAuthenticator;
import com.oneidentity.safeguard.safeguardjava.data.FullResponse;
import com.oneidentity.safeguard.safeguardjava.data.Service;
import com.oneidentity.safeguard.safeguardjava.event.ISafeguardEventListener;
import com.oneidentity.safeguard.safeguardjava.exceptions.SafeguardForJavaException;
import com.oneidentity.safeguard.safeguardjava.restclient.RestClient;

class SafeguardManagementServiceConnection extends SafeguardConnection {

    private final IAuthenticationMechanism authenticationMechanism;
    
    private final RestClient managementClient;

    public SafeguardManagementServiceConnection(IAuthenticationMechanism parentAuthenticationMechanism, String networkAddress) {
        
        super(parentAuthenticationMechanism);
        authenticationMechanism = new ManagementServiceAuthenticator(parentAuthenticationMechanism, networkAddress);

        String safeguardManagementUrl = String.format("https://%s/service/management/v%d",
                this.authenticationMechanism.getNetworkAddress(), this.authenticationMechanism.getApiVersion());
        managementClient = new RestClient(safeguardManagementUrl, authenticationMechanism.isIgnoreSsl(), authenticationMechanism.getValidationCallback());
    }

    public FullResponse JoinSps(ISafeguardSessionsConnection spsConnection, String certificateChain, String sppAddress) 
            throws SafeguardForJavaException {
        throw new SafeguardForJavaException("Management connection cannot be used to join SPS.");
    }
    
    public ISafeguardEventListener GetEventListener() throws SafeguardForJavaException {
        throw new SafeguardForJavaException("Management connection does not support event listeners.");
    }

    public ISafeguardEventListener GetPersistentEventListener() throws SafeguardForJavaException {
        throw new SafeguardForJavaException("Management connection does not support event listeners.");
    }

    @Override
    protected RestClient getClientForService(Service service) throws SafeguardForJavaException {

        if (service == Service.Management) {
            return managementClient;
        }
        throw new SafeguardForJavaException(String.format("%s service cannot be invoked with a management connection.", service.name()));
    }

}

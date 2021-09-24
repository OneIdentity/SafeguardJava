package com.oneidentity.safeguard.safeguardjava;

import com.oneidentity.safeguard.safeguardjava.exceptions.SafeguardForJavaException;

/**
 *  This static class provides static methods for connecting to Safeguard for Privileged Sessions API.
 */
public class SafeguardForPrivilegedSessions {
    /**
     * Connect to Safeguard for Privileged Sessions API using a user name and password.
     *
     *  @param networkAddress   Network address of Safeguard for Privileged Sessions appliance.
     *  @param username         User name to use for authentication.
     *  @param password         User password to use for authentication.
     *  @param ignoreSsl        Ignore server certificate validation.
     * 
     *  @return                 Reusable Safeguard for Privileged Sessions API connection.
     *  @throws SafeguardForJavaException General Safeguard for Java exception.
     */ 
    public static ISafeguardSessionsConnection Connect(String networkAddress, String username,
            char[] password, boolean ignoreSsl) 
            throws SafeguardForJavaException
    {
        return new SafeguardSessionsConnection(networkAddress, username, password, ignoreSsl, null);
    }
    
    //TODO: This class should provide an Connect API with a validationCallback parameter
//    public static ISafeguardSessionsConnection Connect(String networkAddress, String username,
//            char[] password, HostnameVerifier validationCallback) 
//            throws SafeguardForJavaException
//    {
//        return new SafeguardSessionsConnection(networkAddress, username, password, ignoreSsl);
//    }
}

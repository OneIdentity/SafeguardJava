package com.oneidentity.safeguard.safeguardclient;

import com.oneidentity.safeguard.safeguardclient.exceptions.ObjectDisposedException;
import com.oneidentity.safeguard.safeguardclient.exceptions.SafeguardForJavaException;

/**
 *  This is a reusable interface for calling Safeguard A2A without having to continually
 *  pass the client certificate authentication information.
 */
public interface ISafeguardA2AContext
{
    /**
     *  Retrieves a password using Safeguard A2A.
    
     *  @param apiKey   API key corresponding to the configured account.
     *  @return         The password.
     */
    char[] retrievePassword(char[] apiKey) throws ObjectDisposedException, SafeguardForJavaException;

    /**
     *  Gets an A2A event listener. The handler passed in will be registered for the AssetAccountPasswordUpdated
     *  event, which is the only one supported in A2A. You just have to call Start().
    
     *  @param apiKey   API key corresponding to the configured account to listen for.
     *  @param handler  A delegate to call any time the AssetAccountPasswordUpdate event occurs.
     *  @return         The event listener.
     */
//    ISafeguardEventListener GetEventListener(SecureString apiKey, SafeguardEventHandler handler);

    /**
     *  Gets an A2A event listener. The handler passed in will be registered for the AssetAccountPasswordUpdated
     *  event, which is the only one supported in A2A. You just have to call Start().
    
     *  @param apiKey   API key corresponding to the configured account to listen for.
     *  @param handler  A delegate to call any time the AssetAccountPasswordUpdate event occurs.
     *  @return         The event listener.
     */
//    ISafeguardEventListener GetEventListener(SecureString apiKey, SafeguardParsedEventHandler handler);
    
    /**
     *  Dispose of an object
     */
    public void dispose();

}

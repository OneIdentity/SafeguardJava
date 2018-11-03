package com.oneidentity.safeguard.safeguardjava;

import com.oneidentity.safeguard.safeguardjava.data.BrokeredAccessRequest;
import com.oneidentity.safeguard.safeguardjava.event.ISafeguardEventListener;
import com.oneidentity.safeguard.safeguardjava.event.SafeguardEventHandler;
import com.oneidentity.safeguard.safeguardjava.exceptions.ArgumentException;
import com.oneidentity.safeguard.safeguardjava.exceptions.ObjectDisposedException;
import com.oneidentity.safeguard.safeguardjava.exceptions.SafeguardForJavaException;

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
     *  @throws ObjectDisposedException Object has already been disposed.
     *  @throws SafeguardForJavaException General Safeguard for Java exception.
     */
    char[] retrievePassword(char[] apiKey) throws ObjectDisposedException, SafeguardForJavaException;

    /**
     *  Gets an A2A event listener. The handler passed in will be registered for the AssetAccountPasswordUpdated
     *   event, which is the only one supported in A2A. You just have to call Start(). The event listener returned
     *   by this method will not automatically recover from a SignalR timeout which occurs when there is a 30+
     *   second outage. To get an event listener that supports recovering from longer term outages, please use
     *   Safeguard.A2A.Event to request a persistent event listener.
     * 
     *  @param apiKey   API key corresponding to the configured account.
     *  @param handler  A delegate to call any time the AssetAccountPasswordUpdate event occurs.
     *  @return         The event listener.
     *  @throws ObjectDisposedException The object has already been disposed.
     *  @throws ArgumentException Invalid argument.
     */
    ISafeguardEventListener getEventListener(char[] apiKey, SafeguardEventHandler handler) throws ObjectDisposedException, ArgumentException;

    /**
     *  Creates an access request on behalf of another user using Safeguard A2A.
     * 
     *  @param apiKey           API key corresponding to the configured account.
     *  @param accessRequest    The details of the access request to create.
     *  @return                 A JSON string representing the new access request.
     *  @throws ObjectDisposedException Object has already been disposed.
     *  @throws SafeguardForJavaException General Safeguard for Java exception.
     *  @throws ArgumentException Invalid argument
     */
    String BrokerAccessRequest(char[] apiKey, BrokeredAccessRequest accessRequest) throws ObjectDisposedException, SafeguardForJavaException, ArgumentException;
    
    /**
     *  Dispose of an object
     */
    void dispose();

}

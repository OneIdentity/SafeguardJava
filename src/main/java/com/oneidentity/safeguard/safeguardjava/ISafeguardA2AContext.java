package com.oneidentity.safeguard.safeguardjava;

import com.oneidentity.safeguard.safeguardjava.data.KeyFormat;
import com.oneidentity.safeguard.safeguardjava.event.ISafeguardEventListener;
import com.oneidentity.safeguard.safeguardjava.exceptions.ArgumentException;
import com.oneidentity.safeguard.safeguardjava.exceptions.ObjectDisposedException;
import com.oneidentity.safeguard.safeguardjava.exceptions.SafeguardForJavaException;
import com.oneidentity.safeguard.safeguardjava.event.ISafeguardEventHandler;
import java.util.List;

/**
 *  This is a reusable interface for calling Safeguard A2A without having to continually
 *  pass the client certificate authentication information.
 */
public interface ISafeguardA2AContext
{
    /**
     *  Retrieves the list of retrievable accounts for this A2A context.  Listing the retrievable accounts is a
     *  new feature for Safeguard v2.8+, and it needs to be enabled in the A2A configuration.
     
     *  @return          A list of retrievable accounts.
     *  @throws ObjectDisposedException Object has already been disposed.
     *  @throws SafeguardForJavaException General Safeguard for Java exception.
     */ 
    List<IA2ARetrievableAccount> getRetrievableAccounts()  throws ObjectDisposedException, SafeguardForJavaException;
        
    /**
     *  Retrieves a password using Safeguard A2A.
    
     *  @param apiKey   API key corresponding to the configured account.
     *  @return         The password.
     *  @throws ObjectDisposedException Object has already been disposed.
     *  @throws SafeguardForJavaException General Safeguard for Java exception.
     *  @throws ArgumentException Invalid argument.
     */
    char[] retrievePassword(char[] apiKey) throws ObjectDisposedException, SafeguardForJavaException, ArgumentException;

    /**
     * Sets a password using Safeguard A2A.
     *
     * @param apiKey     API key corresponding to the configured account.
     * @param password   Password to set.
     * @throws com.oneidentity.safeguard.safeguardjava.exceptions.ObjectDisposedException
     * @throws com.oneidentity.safeguard.safeguardjava.exceptions.SafeguardForJavaException
     * @throws com.oneidentity.safeguard.safeguardjava.exceptions.ArgumentException
    */ 
    void SetPassword(char[] apiKey, char[] password) throws ObjectDisposedException, SafeguardForJavaException, ArgumentException;
        
    /**
     *  Retrieves an SSH private key using Safeguard A2A.
     *
     *  @param apiKey    API key corresponding to the configured account.
     *  @param keyFormat Format to use when returning private key.
     *  @return           The SSH private key.
     *  @throws ObjectDisposedException Object has already been disposed.
     *  @throws SafeguardForJavaException General Safeguard for Java exception.
     *  @throws ArgumentException Invalid argument.
     */ 
    char[] retrievePrivateKey(char[] apiKey, KeyFormat keyFormat) throws ObjectDisposedException, SafeguardForJavaException, ArgumentException;

    /**
     *  Retrieves an API key secret using Safeguard A2A.
     * 
     *  @param apiKey   API key corresponding to the configured account.
     *  @return         A list of API key secrets.
     *  @throws ObjectDisposedException Object has already been disposed.
     *  @throws SafeguardForJavaException General Safeguard for Java exception.
     *  @throws ArgumentException Invalid argument.
     */ 
    List<IApiKeySecret> retrieveApiKeySecret(char[] apiKey) throws ObjectDisposedException, ArgumentException, SafeguardForJavaException;
        
    /**
     * Sets an SSH private key using Safeguard A2A.
     *
     * @param apiKey        API key corresponding to the configured account.
     * @param privateKey    Private key to set.
     * @param password      Password associated with the private key.
     * @param keyFormat     Format to use when returning private key.              
     * @throws com.oneidentity.safeguard.safeguardjava.exceptions.ObjectDisposedException              
     * @throws com.oneidentity.safeguard.safeguardjava.exceptions.ArgumentException              
     * @throws com.oneidentity.safeguard.safeguardjava.exceptions.SafeguardForJavaException              
     */ 
    void SetPrivateKey(char[] apiKey, char[] privateKey, char[] password, KeyFormat keyFormat) throws ObjectDisposedException, ArgumentException, SafeguardForJavaException;
        
    /**
     *  Gets an A2A event listener. The handler passed in will be registered for the AssetAccountPasswordUpdated
     *   event, which is the only one supported in A2A. You just have to call Start(). The event listener returned
     *   by this method WILL NOT automatically recover from a SignalR timeout which occurs when there is a 30+
     *   second outage. To get an event listener that supports recovering from longer term outages, please use
     *   getPersistentEventListener() to request a persistent event listener.
     * 
     *  @param apiKey   API key corresponding to the configured account to listen for.
     *  @param handler  A delegate to call any time the AssetAccountPasswordUpdate event occurs.
     *  @return         The event listener.
     *  @throws ObjectDisposedException The object has already been disposed.
     *  @throws ArgumentException Invalid argument.
     */
    ISafeguardEventListener getA2AEventListener(char[] apiKey, ISafeguardEventHandler handler) throws ObjectDisposedException, ArgumentException;
    
    /**
     *  Gets an A2A event listener. The handler passed in will be registered for the AssetAccountPasswordUpdated
     *   event, which is the only one supported in A2A. You just have to call Start(). The event listener returned
     *   by this method WILL NOT automatically recover from a SignalR timeout which occurs when there is a 30+
     *   second outage. To get an event listener that supports recovering from longer term outages, please use
     *   getPersistentEventListener() to request a persistent event listener.
     * 
     *  @param apiKeys  A list of API keys corresponding to the configured accounts to listen for.
     *  @param handler  A delegate to call any time the AssetAccountPasswordUpdate event occurs.
     *  @return         The event listener.
     *  @throws ObjectDisposedException The object has already been disposed.
     *  @throws ArgumentException Invalid argument.
     */
    ISafeguardEventListener getA2AEventListener(List<char[]> apiKeys, ISafeguardEventHandler handler) throws ObjectDisposedException, ArgumentException;

    /**
     * Gets a persistent A2A event listener. The handler passed in will be registered for the
     * AssetAccountPasswordUpdated event, which is the only one supported in A2A. You just have to call Start().
     * The event listener returned by this method will not automatically recover from a SignalR timeout which
     * occurs when there is a 30+ second outage.
     *
     * @param apiKey    API key corresponding to the configured account to listen for.
     * @param handler   A delegate to call any time the AssetAccountPasswordUpdate event occurs.
     * @return         The event listener.
     * @throws ObjectDisposedException The object has already been disposed.
     * @throws ArgumentException Invalid argument
     */
    ISafeguardEventListener getPersistentA2AEventListener(char[] apiKey, ISafeguardEventHandler handler) throws ObjectDisposedException, ArgumentException;

    /**
     * Gets a persistent A2A event listener. The handler passed in will be registered for the
     * AssetAccountPasswordUpdated event, which is the only one supported in A2A. You just have to call Start().
     * The event listener returned by this method will not automatically recover from a SignalR timeout which
     * occurs when there is a 30+ second outage.
     *
     * @param apiKeys   A list of API keys corresponding to the configured accounts to listen for.
     * @param handler   A delegate to call any time the AssetAccountPasswordUpdate event occurs.
     * @return         The event listener.
     * @throws ObjectDisposedException The object has already been disposed.
     * @throws ArgumentException Invalid argument
     */
    ISafeguardEventListener getPersistentA2AEventListener(List<char[]> apiKeys, ISafeguardEventHandler handler) throws ObjectDisposedException, ArgumentException;
    
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
    String brokerAccessRequest(char[] apiKey, IBrokeredAccessRequest accessRequest) throws ObjectDisposedException, SafeguardForJavaException, ArgumentException;
    
    /**
     *  Dispose of an object
     */
    void dispose();

}

package com.oneidentity.safeguard.safeguardjava;

import com.oneidentity.safeguard.safeguardjava.data.FullResponse;
import com.oneidentity.safeguard.safeguardjava.data.Method;
import com.oneidentity.safeguard.safeguardjava.data.Service;
import com.oneidentity.safeguard.safeguardjava.event.ISafeguardEventListener;
import com.oneidentity.safeguard.safeguardjava.event.SafeguardEventListener;
import com.oneidentity.safeguard.safeguardjava.exceptions.ArgumentException;
import com.oneidentity.safeguard.safeguardjava.exceptions.ObjectDisposedException;
import com.oneidentity.safeguard.safeguardjava.exceptions.SafeguardForJavaException;
import java.util.Map;

/**
 *  This is the reusable connection interface that can be used to call Safeguard API after
 *  connecting using the API access token obtained during authentication.
 */  
public interface ISafeguardConnection {

    /**
     *  Number of minutes remaining in the lifetime of the Safeguard API access token.
     *  
     *  @return Remaining token life time
     *  @throws ObjectDisposedException Object has already been disposed.
     *  @throws SafeguardForJavaException General Safeguard for Java exception.
     */  
    int getAccessTokenLifetimeRemaining() throws ObjectDisposedException, SafeguardForJavaException;

    /**
     *  Request a new Safeguard API access token with the underlying credentials used to 
     *  initial create the connection.
     *  
     *  @throws ObjectDisposedException Object has already been disposed.
     *  @throws SafeguardForJavaException General Safeguard for Java exception.
     */  
    void refreshAccessToken() throws ObjectDisposedException, SafeguardForJavaException;

    /**
     *  Call a Safeguard API method and get any response as a string. Some Safeguard API
     *  methods will return an empty body. If there is a failure a SafeguardDotNetException
     *  will be thrown.
     *  
     *  @param service              Safeguard service to call.
     *  @param method               Safeguard method type to use.
     *  @param relativeUrl          Relative URL of the service to use.
     *  @param body                 Request body to pass to the method.
     *  @param parameters           Additional parameters to add to the URL.
     *  @param additionalHeaders    Additional headers to add to the request.
     *  @return                     Response body as a string.
     *  @throws ObjectDisposedException Object has already been disposed.
     *  @throws SafeguardForJavaException General Safeguard for Java exception.
     *  @throws ArgumentException Invalid argument.
     */  
    String invokeMethod(Service service, Method method, String relativeUrl,
            String body, Map<String, String> parameters,
            Map<String, String> additionalHeaders)
            throws ObjectDisposedException, SafeguardForJavaException, ArgumentException;

    /**
     *  Call a Safeguard API method and get a detailed response with status code, headers,
     *  and body. If there is a failure a SafeguardDotNetException will be thrown.
     *  
     *  @param service              Safeguard service to call.
     *  @param method               Safeguard method type to use.
     *  @param relativeUrl          Relative URL of the service to use.
     *  @param body                 Request body to pass to the method.
     *  @param parameters           Additional parameters to add to the URL.
     *  @param additionalHeaders    Additional headers to add to the request.
     *  @return                     Response with status code, headers, and body as string.
     *  @throws ObjectDisposedException Object has already been disposed.
     *  @throws SafeguardForJavaException General Safeguard for Java exception.
     *  @throws ArgumentException Invalid argument.
     */  
    FullResponse invokeMethodFull(Service service, Method method, String relativeUrl,
            String body, Map<String, String> parameters,
            Map<String, String> additionalHeaders)
            throws ObjectDisposedException, SafeguardForJavaException, ArgumentException;

    /*
     *  Call a Safeguard API method and get any response as a CSV string. Some Safeguard API
     *  methods will return an empty body. If there is a failure a SafeguardDotNetException
     *  will be thrown.
     * 
     *  @param service              Safeguard service to call.
     *  @param method               Safeguard method type to use.
     *  @param relativeUrl          Relative URL of the service to use.
     *  @param body                 Request body to pass to the method.
     *  @param parameters           Additional parameters to add to the URL.
     *  @param additionalHeaders    Additional headers to add to the request.
     *  @returns                    Response body as a CSV string.
     *  @throws ObjectDisposedException Object has already been disposed.
     *  @throws SafeguardForJavaException General Safeguard for Java exception.
     *  @throws ArgumentException Invalid argument.
     */
    String invokeMethodCsv(Service service, Method method, String relativeUrl,
        String body, Map<String, String> parameters,
        Map<String, String> additionalHeaders)
        throws ObjectDisposedException, SafeguardForJavaException, ArgumentException;
        
    /**
     *  Gets a Safeguard event listener. You will need to call the RegisterEventHandler()
     *  method to establish callbacks. Then, you just have to call Start().  Call Stop()
     *  when you are finished. The event listener returned by this method WILL NOT
     *  automatically recover from a SignalR timeout which occurs when there is a 30+
     *  second outage. To get an event listener that supports recovering from longer term
     *  outages, please use GetPersistentEventListener() to request a persistent event
     *  listener.
     *  
     *  @return The event listener.
     *  @throws ObjectDisposedException Object has already been disposed.
     *  @throws ArgumentException Invalid argument.
     */  
    SafeguardEventListener getEventListener() throws ObjectDisposedException, ArgumentException;
    
    /**
     *  Gets a persistent Safeguard event listener. You will need to call the
     *  RegisterEventHandler() method to establish callbacks. Then, you just have to
     *  call Start().  Call Stop() when you are finished. The event listener returned
     *  by this method WILL automatically recover from a SignalR timeout which occurs
     *  when there is a 30+ second outage.
     *
     *  @return The persistent event listener.
     *  @throws ObjectDisposedException Object has already been disposed.
     *  @throws SafeguardForJavaException General Safeguard for Java exception.
     */
    ISafeguardEventListener getPersistentEventListener() throws ObjectDisposedException, SafeguardForJavaException;

    /**
     *  Call Safeguard API to invalidate current access token and clear its value from
     *  the connection.  In order to continue using the connection you will need to call
     *  RefreshAccessToken().
     * 
     *  @throws ObjectDisposedException Object has already been disposed.
     */
    void logOut() throws ObjectDisposedException;
    
    /**
     *  Disposes of the connection.
     *  
     */  
    void dispose();
    
}

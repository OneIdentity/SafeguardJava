package com.oneidentity.safeguard.safeguardjava;

import com.oneidentity.safeguard.safeguardjava.data.FullResponse;
import com.oneidentity.safeguard.safeguardjava.data.Method;
import com.oneidentity.safeguard.safeguardjava.data.Service;
import com.oneidentity.safeguard.safeguardjava.event.ISafeguardEventListener;
import com.oneidentity.safeguard.safeguardjava.exceptions.ObjectDisposedException;
import com.oneidentity.safeguard.safeguardjava.exceptions.SafeguardForJavaException;
import java.util.Map;

/**
 *  This is the reusable connection interface that can be used to call Safeguard API after
 *  connecting using the API access token obtained during authentication.
 */  
public interface ISafeguardConnection {

    /**
     *  Number of minutes remaining in the lifetime of the API access token.
     *  
     *  @return Remaining token life time
     *  @throws ObjectDisposedException Object has already been disposed.
     *  @throws SafeguardForJavaException General Safeguard for Java exception.
     */  
    int getAccessTokenLifetimeRemaining() throws ObjectDisposedException, SafeguardForJavaException;

    /**
     *  Use the underlying credentials used to initial create the connection to request a
     *  new API access token.
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
     */  
    String invokeMethod(Service service, Method method, String relativeUrl,
            String body, Map<String, String> parameters,
            Map<String, String> additionalHeaders)
            throws ObjectDisposedException, SafeguardForJavaException;

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
     */  
    FullResponse invokeMethodFull(Service service, Method method, String relativeUrl,
            String body, Map<String, String> parameters,
            Map<String, String> additionalHeaders)
            throws ObjectDisposedException, SafeguardForJavaException;

    /**
     *  Gets a Safeguard event listener. You will need to call the RegisterEventHandler()
     *  method to establish callbacks. Then, you just have to call Start().  Call Stop()
     *  when you are finished.
     *  
     *  @return The event listener.
     *  @throws ObjectDisposedException Object has already been disposed.
     */  
    ISafeguardEventListener getEventListener() throws ObjectDisposedException;
    
    /**
     *  Disposes of the connection.
     *  
     */  
    void dispose();
    
}

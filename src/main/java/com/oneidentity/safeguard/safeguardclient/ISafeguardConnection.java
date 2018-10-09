package com.oneidentity.safeguard.safeguardclient;

import com.oneidentity.safeguard.safeguardclient.data.FullResponse;
import com.oneidentity.safeguard.safeguardclient.data.Method;
import com.oneidentity.safeguard.safeguardclient.data.Service;
import com.oneidentity.safeguard.safeguardclient.exceptions.ObjectDisposedException;
import com.oneidentity.safeguard.safeguardclient.exceptions.SafeguardForJavaException;
import java.util.Map;

/**
 *  This is the reusable connection interface that can be used to call Safeguard API after
 *  connecting using the API access token obtained during authentication.
 */  
public interface ISafeguardConnection {

    /**
     *  Number of minutes remaining in the lifetime of the API access token.
     *  
     *  @return
     */  
    int getAccessTokenLifetimeRemaining() throws ObjectDisposedException, SafeguardForJavaException;

    /**
     *  Use the underlying credentials used to initial create the connection to request a
     *  new API access token.
     *  
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
     */  
    FullResponse invokeMethodFull(Service service, Method method, String relativeUrl,
            String body, Map<String, String> parameters,
            Map<String, String> additionalHeaders)
            throws ObjectDisposedException, SafeguardForJavaException;

//    /**
//     *  Gets a Safeguard event listener. You will need to call the RegisterEventHandler()
//     *  method to establish callbacks. Then, you just have to call Start().  Call Stop()
//     *  when you are finished.
//     *  
//     *  @return   The event listener.
//     */  
//    ISafeguardEventListener GetEventListener();
    
    /**
     *  Disposes of the connection.
     *  
     *  @return
     */  
    void dispose();
    
}

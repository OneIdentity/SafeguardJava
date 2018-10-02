package com.oneidentity.safeguard.safeguardclient;

import com.oneidentity.safeguard.safeguardclient.data.FullResponse;
import com.oneidentity.safeguard.safeguardclient.data.Method;
import com.oneidentity.safeguard.safeguardclient.data.Service;
import com.oneidentity.safeguard.safeguardclient.exceptions.ObjectDisposedException;
import com.oneidentity.safeguard.safeguardclient.exceptions.SafeguardForJavaException;
import java.util.Map;

/// <summary>
/// This is the reusable connection interface that can be used to call Safeguard API after
/// connecting using the API access token obtained during authentication.
/// </summary>
public interface ISafeguardConnection {

    /// <summary>
    /// Number of minutes remaining in the lifetime of the API access token.
    /// </summary>
    /// <returns></returns>
    int GetAccessTokenLifetimeRemaining() throws ObjectDisposedException, SafeguardForJavaException;

    /// <summary>
    /// Use the underlying credentials used to initial create the connection to request a
    /// new API access token.
    /// </summary>
    void RefreshAccessToken() throws ObjectDisposedException, SafeguardForJavaException;

    /// <summary>
    /// Call a Safeguard API method and get any response as a string. Some Safeguard API
    /// methods will return an empty body. If there is a failure a SafeguardDotNetException
    /// will be thrown.
    /// </summary>
    /// <param name="service">Safeguard service to call.</param>
    /// <param name="method">Safeguard method type to use.</param>
    /// <param name="relativeUrl">Relative URL of the service to use.</param>
    /// <param name="body">Request body to pass to the method.</param>
    /// <param name="parameters">Additional parameters to add to the URL.</param>
    /// <param name="additionalHeaders">Additional headers to add to the request.</param>
    /// <returns>Response body as a string.</returns>
    String InvokeMethod(Service service, Method method, String relativeUrl,
            String body, Map<String, String> parameters,
            Map<String, String> additionalHeaders)
            throws ObjectDisposedException, SafeguardForJavaException;

    /// <summary>
    /// Call a Safeguard API method and get a detailed response with status code, headers,
    /// and body. If there is a failure a SafeguardDotNetException will be thrown.
    /// </summary>
    /// <param name="service">Safeguard service to call.</param>
    /// <param name="method">Safeguard method type to use.</param>
    /// <param name="relativeUrl">Relative URL of the service to use.</param>
    /// <param name="body">Request body to pass to the method.</param>
    /// <param name="parameters">Additional parameters to add to the URL.</param>
    /// <param name="additionalHeaders">Additional headers to add to the request.</param>
    /// <returns>Response with status code, headers, and body as string.</returns>
    FullResponse InvokeMethodFull(Service service, Method method, String relativeUrl,
            String body, Map<String, String> parameters,
            Map<String, String> additionalHeaders)
            throws ObjectDisposedException, SafeguardForJavaException;

//    /// <summary>
//    /// Gets a Safeguard event listener. You will need to call the RegisterEventHandler()
//    /// method to establish callbacks. Then, you just have to call Start().  Call Stop()
//    /// when you are finished.
//    /// </summary>
//    /// <returns>The event listener.</returns>
//    ISafeguardEventListener GetEventListener();
    
    /// <summary>
    /// Disposes of the connection.
    /// </summary>
    /// <returns></returns>
    void Dispose();
    
}

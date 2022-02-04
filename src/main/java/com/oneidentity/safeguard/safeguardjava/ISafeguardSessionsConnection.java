package com.oneidentity.safeguard.safeguardjava;

import com.oneidentity.safeguard.safeguardjava.data.FullResponse;
import com.oneidentity.safeguard.safeguardjava.data.Method;
import com.oneidentity.safeguard.safeguardjava.exceptions.ArgumentException;
import com.oneidentity.safeguard.safeguardjava.exceptions.ObjectDisposedException;
import com.oneidentity.safeguard.safeguardjava.exceptions.SafeguardForJavaException;

/**
 * This is the reusable connection interface that can be used to call SPS API.
 */
public interface ISafeguardSessionsConnection {
    
    /**
     *  Call a Safeguard for Privileged Sessions API method and get any response as a string.
     *  If there is a failure a SafeguardDotNetException will be thrown.
     * 
     *  @param method               Safeguard method type to use.
     *  @param relativeUrl          Relative URL of the service to use.
     *  @param body                 Request body to pass to the method.
     *  @return                     Response body as a string.
     *  @throws ObjectDisposedException Object has already been disposed.
     *  @throws SafeguardForJavaException General Safeguard for Java exception.
     *  @throws ArgumentException Invalid argument.
     */  
    String InvokeMethod(Method method, String relativeUrl, String body)
            throws ObjectDisposedException, SafeguardForJavaException, ArgumentException;

    /**
     *  Call a Safeguard for Privileged Sessions API method and get a detailed response
     *  with status code, headers, and body. If there is a failure a SafeguardDotNetException
     *  will be thrown.
     *
     *  @param method               Safeguard method type to use.
     *  @param relativeUrl          Relative URL of the service to use.
     *  @param body                 Request body to pass to the method.
     *  @return                     Response with status code, headers, and body as string.
     *  @throws ObjectDisposedException Object has already been disposed.
     *  @throws SafeguardForJavaException General Safeguard for Java exception.
     *  @throws ArgumentException Invalid argument.
     */  
    FullResponse InvokeMethodFull(Method method, String relativeUrl, String body)
            throws ObjectDisposedException, SafeguardForJavaException, ArgumentException;
    
    /**
     * Provides support for HTTP streaming requests
     * 
     * @return returns ISpsStreamingRequest
     * @throws com.oneidentity.safeguard.safeguardjava.exceptions.ObjectDisposedException
     */
    ISpsStreamingRequest getStream() throws ObjectDisposedException;
}

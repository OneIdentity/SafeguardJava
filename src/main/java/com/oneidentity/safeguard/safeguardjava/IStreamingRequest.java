package com.oneidentity.safeguard.safeguardjava;

import com.oneidentity.safeguard.safeguardjava.data.Service;
import com.oneidentity.safeguard.safeguardjava.exceptions.ArgumentException;
import com.oneidentity.safeguard.safeguardjava.exceptions.ObjectDisposedException;
import com.oneidentity.safeguard.safeguardjava.exceptions.SafeguardForJavaException;
import java.util.Map;

/**
 * HTTP streaming request methods
 */
public interface IStreamingRequest {

    /**
     * Call a Safeguard POST API providing a stream as request content. If there is a 
     * failure a SafeguardDotNetException will be thrown.
     * 
     * @param service           Safeguard service to call.
     * @param relativeUrl       Relative URL of the service to use.
     * @param stream            Stream to upload as request content.
     * @param progressCallback  Optionally report upload progress.
     * @param parameters        Additional parameters to add to the URL.
     * @param additionalHeaders Additional headers to add to the request.
     * @return                  Response body as a string.
     * @throws ObjectDisposedException Object has already been disposed.
     * @throws SafeguardForJavaException General Safeguard for Java exception.
     * @throws ArgumentException Invalid argument.
     */ 
    String uploadStream(Service service, String relativeUrl, byte[] stream, IProgressCallback progressCallback, 
            Map<String, String> parameters, Map<String, String> additionalHeaders) 
            throws SafeguardForJavaException, ArgumentException, ObjectDisposedException;

    /**
     * Call a Safeguard GET API providing an output file path to which streaming download data will
     * be written. If there is a failure a SafeguardDotNetException will be thrown.
     * 
     * @param service           Safeguard service to call.
     * @param relativeUrl       Relative URL of the service to use.
     * @param outputFilePath    Full path to the file where download will be written.
     * @param progressCallback  Optionally report upload progress.
     * @param parameters        Additional parameters to add to the URL.
     * @param additionalHeaders Additional headers to add to the request.
     * @throws ObjectDisposedException Object has already been disposed.
     * @throws SafeguardForJavaException General Safeguard for Java exception.
     * @throws ArgumentException Invalid argument.
     */ 
    void downloadStream(Service service, String relativeUrl, String outputFilePath, IProgressCallback progressCallback, 
            Map<String, String> parameters, Map<String, String> additionalHeaders) 
            throws SafeguardForJavaException, ArgumentException, ObjectDisposedException;
}

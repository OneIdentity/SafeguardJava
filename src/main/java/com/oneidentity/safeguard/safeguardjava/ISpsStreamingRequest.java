package com.oneidentity.safeguard.safeguardjava;

import com.oneidentity.safeguard.safeguardjava.exceptions.ArgumentException;
import com.oneidentity.safeguard.safeguardjava.exceptions.SafeguardForJavaException;
import java.util.Map;

/**
 * SPS streaming request methods
 */
public interface ISpsStreamingRequest {

    /**
     * Call a Safeguard Sps POST API providing a stream as request content. If
     * there is a failure a SafeguardDotNetException will be thrown.
     *
     * @param relativeUrl Relative URL of the service to use.
     * @param stream Stream to upload as request content.
     * @param progressCallback Optionally report upload progress.
     * @param parameters Additional parameters to add to the URL.
     * @param additionalHeaders Additional headers to add to the request.
     * @return Response body as a string.
     * @throws
     * com.oneidentity.safeguard.safeguardjava.exceptions.SafeguardForJavaException
     * @throws
     * com.oneidentity.safeguard.safeguardjava.exceptions.ArgumentException
     */
    String uploadStream(String relativeUrl, byte[] stream, IProgressCallback progressCallback,
            Map<String, String> parameters, Map<String, String> additionalHeaders)
            throws SafeguardForJavaException, ArgumentException;
    
    /**
     * Call a Safeguard Sps POST API providing a file as request content. If
     * there is a failure a SafeguardDotNetException will be thrown.
     *
     * @param relativeUrl Relative URL of the service to use.
     * @param fileName File to upload as request content.
     * @param parameters Additional parameters to add to the URL.
     * @param additionalHeaders Additional headers to add to the request.
     * @return Response body as a string.
     * @throws
     * com.oneidentity.safeguard.safeguardjava.exceptions.SafeguardForJavaException
     * @throws
     * com.oneidentity.safeguard.safeguardjava.exceptions.ArgumentException
     */
    String uploadStream(String relativeUrl, String fileName, 
            Map<String, String> parameters, Map<String, String> additionalHeaders)
            throws SafeguardForJavaException, ArgumentException;
    
}

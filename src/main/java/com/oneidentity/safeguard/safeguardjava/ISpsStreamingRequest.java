package com.oneidentity.safeguard.safeguardjava;

import com.oneidentity.safeguard.safeguardjava.exceptions.ArgumentException;
import com.oneidentity.safeguard.safeguardjava.exceptions.SafeguardForJavaException;
import java.io.InputStream;
import java.io.OutputStream;
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
     * @throws SafeguardForJavaException General Safeguard for Java exception.
     * @throws ArgumentException Invalid argument.
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
     * @throws SafeguardForJavaException General Safeguard for Java exception.
     * @throws ArgumentException Invalid argument.
     */
    String uploadStream(String relativeUrl, String fileName, 
            Map<String, String> parameters, Map<String, String> additionalHeaders)
            throws SafeguardForJavaException, ArgumentException;
 
    /**
     * Call a Safeguard Sps GET API returning output as a stream. The caller takes ownership of the
     * StreamResponse and should dispose it when finished. 
     * If there is a failure a SafeguardDotNetException will be thrown.
     * 
     * @param relativeUrl Relative URL of the service to use.
     * @param parameters Additional parameters to add to the URL.
     * @param additionalHeaders Additional headers to add to the request.
     * @return A StreamResponse.
     * @throws SafeguardForJavaException General Safeguard for Java exception.
     * @throws ArgumentException Invalid argument.
     */
    StreamResponse downloadStream(String relativeUrl, Map<String, String> parameters, Map<String, String> additionalHeaders)
            throws SafeguardForJavaException, ArgumentException;

    /**
     * Call a Safeguard GET API providing an output file path to which streaming download data will
     * be written. If there is a failure a SafeguardDotNetException will be thrown.
     * 
     * @param relativeUrl       Relative URL of the service to use.
     * @param outputFilePath    Full path to the file where download will be written.
     * @param progressCallback  Optionally report upload progress.
     * @param parameters        Additional parameters to add to the URL.
     * @param additionalHeaders Additional headers to add to the request.
     * @throws SafeguardForJavaException General Safeguard for Java exception.
     * @throws ArgumentException Invalid argument.
     */
    void downloadStream(String relativeUrl, String outputFilePath, IProgressCallback progressCallback, 
            Map<String, String> parameters, Map<String, String> additionalHeaders)
            throws SafeguardForJavaException, ArgumentException;
    
}

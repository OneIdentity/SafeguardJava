package com.oneidentity.safeguard.safeguardjava;

import com.oneidentity.safeguard.safeguardjava.data.FullResponse;
import com.oneidentity.safeguard.safeguardjava.data.Method;
import com.oneidentity.safeguard.safeguardjava.exceptions.ArgumentException;
import com.oneidentity.safeguard.safeguardjava.exceptions.SafeguardForJavaException;
import com.oneidentity.safeguard.safeguardjava.restclient.OutputStreamProgress;
import com.oneidentity.safeguard.safeguardjava.restclient.RestClient;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Map;
import org.apache.http.client.methods.CloseableHttpResponse;

class SpsStreamingRequest implements ISpsStreamingRequest {

    private final Integer DefaultBufferSize = 81920;
    private RestClient client;

    SpsStreamingRequest(RestClient client) {
        this.client = client;
    }

    @Override
    public String uploadStream(String relativeUrl, byte[] stream, IProgressCallback progressCallback,
            Map<String, String> parameters, Map<String, String> additionalHeaders)
            throws SafeguardForJavaException, ArgumentException {

        if (Utils.isNullOrEmpty(relativeUrl)) {
            throw new ArgumentException("Parameter relativeUrl cannot be null or empty");
        }
        if (client == null) {
            throw new ArgumentException("Invalid or unauthenticated SPS connection");
        }

        CloseableHttpResponse response = null;

        SafeguardConnection.logRequestDetails(Method.Post, client.getBaseURL() + "/" + relativeUrl, parameters, additionalHeaders);

        response = client.execPOSTBytes(relativeUrl, parameters, additionalHeaders, null, stream, progressCallback);

        if (response == null) {
            throw new SafeguardForJavaException(String.format("Unable to connect to SPS service %s", client.getBaseURL()));
        }

        String reply = Utils.getResponse(response);

        if (!Utils.isSuccessful(response.getStatusLine().getStatusCode())) {
            throw new SafeguardForJavaException("Error returned from SPS API, Error: "
                    + String.format("%d %s", response.getStatusLine().getStatusCode(), reply));
        }

        FullResponse fullResponse = new FullResponse(response.getStatusLine().getStatusCode(), response.getAllHeaders(), reply);

        SafeguardConnection.logResponseDetails(fullResponse);

        return fullResponse.getBody();
    }
    
    @Override
    public String uploadStream(String relativeUrl, String fileName, 
            Map<String, String> parameters, Map<String, String> additionalHeaders)
            throws SafeguardForJavaException, ArgumentException {

        if (Utils.isNullOrEmpty(relativeUrl)) {
            throw new ArgumentException("Parameter relativeUrl cannot be null or empty");
        }
        if (client == null) {
            throw new ArgumentException("Invalid or unauthenticated SPS connection");
        }

        CloseableHttpResponse response = null;

        SafeguardConnection.logRequestDetails(Method.Post, client.getBaseURL() + "/" + relativeUrl, parameters, additionalHeaders);

        response = client.execPOSTFile(relativeUrl, parameters, additionalHeaders, null, fileName);

        if (response == null) {
            throw new SafeguardForJavaException(String.format("Unable to connect to SPS service %s", client.getBaseURL()));
        }

        String reply = Utils.getResponse(response);

        if (!Utils.isSuccessful(response.getStatusLine().getStatusCode())) {
            throw new SafeguardForJavaException("Error returned from SPS API, Error: "
                    + String.format("%d %s", response.getStatusLine().getStatusCode(), reply));
        }

        FullResponse fullResponse = new FullResponse(response.getStatusLine().getStatusCode(), response.getAllHeaders(), reply);

        SafeguardConnection.logResponseDetails(fullResponse);

        return fullResponse.getBody();
    }
    
    
    @Override
    public StreamResponse downloadStream(String relativeUrl, Map<String, String> parameters, Map<String, String> additionalHeaders) 
            throws SafeguardForJavaException, ArgumentException {
        
        if (Utils.isNullOrEmpty(relativeUrl)) {
            throw new ArgumentException("Parameter relativeUrl cannot be null or empty");
        }
        if (client == null) {
            throw new ArgumentException("Invalid or unauthenticated SPS connection");
        }

        CloseableHttpResponse response = null;

        SafeguardConnection.logRequestDetails(Method.Get, client.getBaseURL() + "/" + relativeUrl, parameters, additionalHeaders);

        response = client.execGETBytes(relativeUrl, parameters, additionalHeaders, null, null);

        if (response == null) {
            throw new SafeguardForJavaException(String.format("Unable to connect to SPS service %s", client.getBaseURL()));
        }

        if (!Utils.isSuccessful(response.getStatusLine().getStatusCode())) {
            String reply = Utils.getResponse(response);
            throw new SafeguardForJavaException("Error returned from SPS API, Error: "
                    + String.format("%d %s", response.getStatusLine().getStatusCode(), reply));
        }

        FullResponse fullResponse = new FullResponse(response.getStatusLine().getStatusCode(), response.getAllHeaders(), null);
        SafeguardConnection.logResponseDetails(fullResponse);

        return new StreamResponse(response);
    }
    
    @Override
    public void downloadStream(String relativeUrl, String outputFilePath, IProgressCallback progressCallback, 
            Map<String, String> parameters, Map<String, String> additionalHeaders)
            throws SafeguardForJavaException, ArgumentException {
        
        StreamResponse streamResponse = null;
        InputStream input = null;
        OutputStream output = null;
        byte[] buffer = new byte[DefaultBufferSize];

        try {
            streamResponse = downloadStream(relativeUrl, parameters, additionalHeaders);
            input = streamResponse.getStream();
            output = new OutputStreamProgress(new FileOutputStream(outputFilePath), progressCallback, streamResponse.getContentLength());

            for (int length; (length = input.read(buffer)) > 0;) {
                output.write(buffer, 0, length);
            }
        } catch (Exception ex) {
            throw new SafeguardForJavaException(String.format("Unable to download %s", outputFilePath), ex);
        } finally {
            if (output != null) try { output.close(); } catch (IOException logOrIgnore) {}
            if (streamResponse != null) streamResponse.dispose();
        }
    }

}

package com.oneidentity.safeguard.safeguardjava;

import com.oneidentity.safeguard.safeguardjava.data.FullResponse;
import com.oneidentity.safeguard.safeguardjava.data.Method;
import com.oneidentity.safeguard.safeguardjava.exceptions.ArgumentException;
import com.oneidentity.safeguard.safeguardjava.exceptions.SafeguardForJavaException;
import com.oneidentity.safeguard.safeguardjava.restclient.RestClient;
import java.util.Map;
import org.apache.http.client.methods.CloseableHttpResponse;

class SpsStreamingRequest implements ISpsStreamingRequest {

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
    
}

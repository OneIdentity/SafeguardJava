package com.oneidentity.safeguard.safeguardjava;

import com.oneidentity.safeguard.safeguardjava.authentication.IAuthenticationMechanism;
import com.oneidentity.safeguard.safeguardjava.data.FullResponse;
import com.oneidentity.safeguard.safeguardjava.data.Method;
import com.oneidentity.safeguard.safeguardjava.data.Service;
import com.oneidentity.safeguard.safeguardjava.exceptions.ArgumentException;
import com.oneidentity.safeguard.safeguardjava.exceptions.ObjectDisposedException;
import com.oneidentity.safeguard.safeguardjava.exceptions.SafeguardForJavaException;
import com.oneidentity.safeguard.safeguardjava.restclient.OutputStreamProgress;
import com.oneidentity.safeguard.safeguardjava.restclient.RestClient;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Map;
import org.apache.http.client.methods.CloseableHttpResponse;

class StreamingRequest implements IStreamingRequest {

    private final Integer DefaultBufferSize = 81920;
    private final SafeguardConnection safeguardConnection;
    private final IAuthenticationMechanism authenticationMechanism;

    StreamingRequest(SafeguardConnection safeguardConnection)
    {
        this.safeguardConnection = safeguardConnection;
        this.authenticationMechanism = safeguardConnection.getAuthenticationMechanism();
    }

    @Override
    public String uploadStream(Service service, String relativeUrl, byte[] stream, IProgressCallback progressCallback, Map<String, String> parameters, Map<String, String> additionalHeaders)
            throws SafeguardForJavaException, ArgumentException, ObjectDisposedException {
        
        if (safeguardConnection.isDisposed())
            throw new ObjectDisposedException("SafeguardConnection");
        if (Utils.isNullOrEmpty(relativeUrl))
            throw new ArgumentException("Parameter relativeUrl may not be null or empty");

        RestClient client = safeguardConnection.getClientForService(service);
        if (!authenticationMechanism.isAnonymous() && !authenticationMechanism.hasAccessToken()) {
            throw new SafeguardForJavaException("Access token is missing due to log out, you must refresh the access token to invoke a method");
        }
        
        Map<String,String> headers = safeguardConnection.prepareHeaders(additionalHeaders, service);
        CloseableHttpResponse response = null;
        
        SafeguardConnection.logRequestDetails(Method.Post, client.getBaseURL() + "/" + relativeUrl, parameters, additionalHeaders);

        response = client.execPOSTBytes(relativeUrl, parameters, headers, null, stream, progressCallback);

        if (response == null) {
            throw new SafeguardForJavaException(String.format("Unable to connect to web service %s", client.getBaseURL()));
        }

        String reply = Utils.getResponse(response);

        if (!Utils.isSuccessful(response.getStatusLine().getStatusCode())) {
            throw new SafeguardForJavaException("Error returned from Safeguard API, Error: "
                    + String.format("%d %s", response.getStatusLine().getStatusCode(), reply));
        }

        FullResponse fullResponse = new FullResponse(response.getStatusLine().getStatusCode(), response.getAllHeaders(), reply);

        SafeguardConnection.logResponseDetails(fullResponse);

        return fullResponse.getBody();
    }

    @Override
    public void downloadStream(Service service, String relativeUrl, String outputFilePath, IProgressCallback progressCallback, Map<String, String> parameters, Map<String, String> additionalHeaders)
            throws SafeguardForJavaException, ArgumentException, ObjectDisposedException {
        
        if (safeguardConnection.isDisposed())
            throw new ObjectDisposedException("SafeguardConnection");
        if (Utils.isNullOrEmpty(relativeUrl))
            throw new ArgumentException("Parameter relativeUrl may not be null or empty");

        RestClient client = safeguardConnection.getClientForService(service);
        if (!authenticationMechanism.isAnonymous() && !authenticationMechanism.hasAccessToken()) {
            throw new SafeguardForJavaException("Access token is missing due to log out, you must refresh the access token to invoke a method");
        }
        
        Map<String,String> headers = safeguardConnection.prepareHeaders(additionalHeaders, service);
        
        SafeguardConnection.logRequestDetails(Method.Get, client.getBaseURL() + "/" + relativeUrl, parameters, additionalHeaders);

        CloseableHttpResponse response = client.execGETBytes(relativeUrl, parameters, headers, null, progressCallback);

        if (response == null) {
            throw new SafeguardForJavaException(String.format("Unable to connect to web service %s", client.getBaseURL()));
        }

        if (!Utils.isSuccessful(response.getStatusLine().getStatusCode())) {
            String reply = Utils.getResponse(response);
            throw new SafeguardForJavaException("Error returned from Safeguard API, Error: "
                    + String.format("%d %s", response.getStatusLine().getStatusCode(), reply));
        }

        InputStream input = null;
        OutputStream output = null;
        byte[] buffer = new byte[DefaultBufferSize];

        try {
            input = response.getEntity().getContent();
            output = new OutputStreamProgress(new FileOutputStream(outputFilePath), progressCallback, response.getEntity().getContentLength());

            for (int length; (length = input.read(buffer)) > 0;) {
                output.write(buffer, 0, length);
            }
        } catch (Exception ex) {
            throw new SafeguardForJavaException(String.format("Unable to download %s", outputFilePath), ex);
        } finally {
            if (output != null) try { output.close(); } catch (IOException logOrIgnore) {}
            if (input != null) try { input.close(); } catch (IOException logOrIgnore) {}
        }
        
        FullResponse fullResponse = new FullResponse(response.getStatusLine().getStatusCode(), response.getAllHeaders(), null);

        SafeguardConnection.logResponseDetails(fullResponse);
    }
}

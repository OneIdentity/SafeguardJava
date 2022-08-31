package com.oneidentity.safeguard.safeguardjava;

import static com.oneidentity.safeguard.safeguardjava.SafeguardConnection.logRequestDetails;
import static com.oneidentity.safeguard.safeguardjava.SafeguardConnection.logResponseDetails;
import com.oneidentity.safeguard.safeguardjava.data.FullResponse;
import com.oneidentity.safeguard.safeguardjava.data.JsonBody;
import com.oneidentity.safeguard.safeguardjava.data.Method;
import com.oneidentity.safeguard.safeguardjava.exceptions.ArgumentException;
import com.oneidentity.safeguard.safeguardjava.exceptions.ObjectDisposedException;
import com.oneidentity.safeguard.safeguardjava.exceptions.SafeguardForJavaException;
import com.oneidentity.safeguard.safeguardjava.restclient.RestClient;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.HostnameVerifier;
import org.apache.http.Header;
import org.apache.http.client.methods.CloseableHttpResponse;

/**
 * This is the reusable connection interface that can be used to call SPS API.
 */
class SafeguardSessionsConnection implements ISafeguardSessionsConnection {

    private boolean disposed;

    private RestClient client;

    public SafeguardSessionsConnection(String networkAddress, String username,
            char[] password, boolean ignoreSsl, HostnameVerifier validationCallback)
            throws SafeguardForJavaException {

        String spsApiUrl = String.format("https://%s/api", networkAddress);
        client = new RestClient(spsApiUrl, username, password, ignoreSsl, validationCallback);

        Map<String, String> headers = new HashMap<>();

        Logger.getLogger(SafeguardSessionsConnection.class.getName()).log(Level.FINEST, "Starting authentication.");
        logRequestDetails(Method.Get, client.getBaseURL() + "/" + "authentication", null, null);

        CloseableHttpResponse response = client.execGET("authentication", null, null, null);

        if (response == null) {
            throw new SafeguardForJavaException(String.format("Unable to authenticate to SPS %s", networkAddress));
        }

        String reply = Utils.getResponse(response);

        if (!Utils.isSuccessful(response.getStatusLine().getStatusCode())) {
            throw new SafeguardForJavaException("Error returned from Safeguard API, Error: "
                    + String.format("%d %s", response.getStatusLine().getStatusCode(), reply));
        }

        Header authCookie = response.getFirstHeader("Set-Cookie");
        if (authCookie != null) {
            client.addSessionId(authCookie.getValue());
        }

        Logger.getLogger(SafeguardSessionsConnection.class.getName()).log(Level.FINEST, String.format("Response content: $s", reply));
    }

    @Override
    public String InvokeMethod(Method method, String relativeUrl, String body)
            throws ObjectDisposedException, SafeguardForJavaException, ArgumentException {

        return InvokeMethodFull(method, relativeUrl, body).getBody();
    }

    /**
     * Call a SafeguardForPrivilegedSessions API method and get a detailed
     * response with status code, headers, and body. If there is a failure a
     * SafeguardDotNetException will be thrown.
     *
     * @param method HTTP method type to use.
     * @param relativeUrl The url.
     * @param body Request body to pass to the method.
     *
     * @return Response with status code, headers, and body as string.
     */
    @Override
    //TODO: This API should have an additionalHeaders parameter
    //TODO: This API should have an parameters parameter
    //TODO: This API should have an timeout parameter
    public FullResponse InvokeMethodFull(Method method, String relativeUrl, String body)
            throws ObjectDisposedException, SafeguardForJavaException, ArgumentException {

        if (disposed) {
            throw new ObjectDisposedException("SafeguardSessionsConnection");
        }
        if (Utils.isNullOrEmpty(relativeUrl)) {
            throw new ArgumentException("Parameter relativeUrl may not be null or empty");
        }

        Logger.getLogger(SafeguardSessionsConnection.class.getName()).log(Level.FINEST, String.format("Invoking method on sps: $s", relativeUrl));

        CloseableHttpResponse response = null;

        logRequestDetails(method, client.getBaseURL() + "/" + relativeUrl, null, null);

        switch (method) {
            case Get:
                response = client.execGET(relativeUrl, null, null, null);
                break;
            case Post:
                response = client.execPOST(relativeUrl, null, null, null, new JsonBody(body));
                break;
            case Put:
                response = client.execPUT(relativeUrl, null, null, null, new JsonBody(body));
                break;
            case Delete:
                response = client.execDELETE(relativeUrl, null, null, null);
                break;
        }

        if (response == null) {
            throw new SafeguardForJavaException(String.format("Unable to connect to web service %s", client.getBaseURL()));
        }

        String reply = Utils.getResponse(response);

        if (!Utils.isSuccessful(response.getStatusLine().getStatusCode())) {
            throw new SafeguardForJavaException("Error returned from Safeguard API, Error: "
                    + String.format("%d %s", response.getStatusLine().getStatusCode(), reply));
        }

        Logger.getLogger(SafeguardSessionsConnection.class.getName()).log(Level.FINEST, String.format("Invoking method finished: $s", reply));

        FullResponse fullResponse = new FullResponse(response.getStatusLine().getStatusCode(), response.getAllHeaders(), reply);

        logResponseDetails(fullResponse);

        return fullResponse;
    }

    @Override
    public ISpsStreamingRequest getStreamingRequest() throws ObjectDisposedException {
        if (disposed) {
            throw new ObjectDisposedException("SafeguardSessionsConnection");
        }

        return new SpsStreamingRequest(this.client);
    }

    boolean isDisposed() {
        return disposed;
    }

    public void dispose() {
        if (client != null) {
            client = null;
        }
        disposed = true;
    }

    protected void finalize() throws Throwable {
        try {
            dispose();
        } finally {
            disposed = true;
            super.finalize();
        }
    }

}

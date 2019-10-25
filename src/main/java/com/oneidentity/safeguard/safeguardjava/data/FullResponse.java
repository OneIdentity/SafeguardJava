package com.oneidentity.safeguard.safeguardjava.data;

import java.util.Arrays;
import java.util.List;
import org.apache.http.Header;


/**
 * A simple class for returning extended information from a Safeguard API method call.
 */
public class FullResponse {
    
    private int statusCode;
    private Header[] headers;
    private String body;

    public FullResponse(int statusCode, Header[] headers, String body) {
        this.statusCode = statusCode;
        this.headers = headers;
        this.body = body;
    }

    public int getStatusCode() {
        return statusCode;
    }

    public void setStatusCode(int statusCode) {
        this.statusCode = statusCode;
    }

    public List<Header> getHeaders() {
        return Arrays.asList(headers);
    }

    public void setHeaders(Header[] headers) {
        this.headers = headers;
    }

    public String getBody() {
        return body;
    }

    public void setBody(String body) {
        this.body = body;
    }
    
}

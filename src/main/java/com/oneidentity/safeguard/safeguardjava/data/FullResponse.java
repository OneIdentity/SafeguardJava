package com.oneidentity.safeguard.safeguardjava.data;

import javax.ws.rs.core.MultivaluedMap;

/**
 * A simple class for returning extended information from a Safeguard API method call.
 */
public class FullResponse {
    
    private int statusCode;
//    private MultivaluedMap<String, Object> headers;
    private MultivaluedMap<String, String> headers;
    private String body;

//    public FullResponse(int statusCode, MultivaluedMap<String,Object> headers, String body) {
    public FullResponse(int statusCode, MultivaluedMap<String,String> headers, String body) {
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

//    public MultivaluedMap<String, Object> getHeaders() {
    public MultivaluedMap<String, String> getHeaders() {
        return headers;
    }

//    public void setHeaders(MultivaluedMap<String, Object> headers) {
    public void setHeaders(MultivaluedMap<String, String> headers) {
        this.headers = headers;
    }

    public String getBody() {
        return body;
    }

    public void setBody(String body) {
        this.body = body;
    }
    
}

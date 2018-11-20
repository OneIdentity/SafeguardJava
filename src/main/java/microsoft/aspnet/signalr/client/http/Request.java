/*
Copyright (c) Microsoft Open Technologies, Inc.
All Rights Reserved
See License.txt in the project root for license information.
*/

package microsoft.aspnet.signalr.client.http;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import microsoft.aspnet.signalr.client.*;

/**
 * Represents an HTTP Request
 */
public class Request {

    private String mVerb;

    private String mContent;

    private HashMap<String, String> mHeaders = new HashMap<>();

    private String mUrl;

    /**
     * Initializes a request with an HTTP verb
     * 
     * @param httpVerb
     *            the HTTP verb
     */
    public Request(String httpVerb) {
        mVerb = httpVerb;
    }

    /**
     * Sets the request content
     * @param content Content
     */
    public void setContent(String content) {
        mContent = content;
    }

    /**
     * Returns the request content
     * @return String Content
     */
    public String getContent() {
        return mContent;
    }

    /**
     * Sets the request content with a single name-value pair, using form
     * encoding
     * 
     * @param name
     *            The name for the form data
     * @param value
     *            The value for the form data
     */
    public void setFormContent(String name, String value) {
        List<Entry<String, String>> formValues = new ArrayList<>();
        formValues.add(new SimpleEntry<>(name, value));

        setFormContent(formValues);
    }

    /**
     * Sets the request content with several name-value pairs, using form
     * encoding
     * 
     * @param formValues
     *            The name-value pairs
     */
    public void setFormContent(List<Entry<String, String>> formValues) {
        StringBuilder sb = new StringBuilder();

        for (Entry<String, String> entry : formValues) {
            try {
                sb.append(String.format("%s=%s&", URLEncoder.encode(entry.getKey(), Constants.UTF8_NAME),
                        URLEncoder.encode(entry.getValue(), Constants.UTF8_NAME)));
            } catch (UnsupportedEncodingException e) {
            }
        }

        mContent = sb.toString();
    }

    /**
     * Returns the request headers
     * @return Map Headers
     */
    public Map<String, String> getHeaders() {
        HashMap<String, String> copy = new HashMap<>();
        copy.putAll(mHeaders);

        return copy;
    }

    /**
     * Sets the request headers
     * @param headers Headers
     */
    public void setHeaders(Map<String, String> headers) {
        mHeaders = new HashMap<>();

        if (headers != null) {
            mHeaders.putAll(headers);
        }
    }

    /**
     * Adds a header to the request
     * 
     * @param name
     *            The header name
     * @param value
     *            The header value
     */
    public void addHeader(String name, String value) {
        mHeaders.put(name, value);
    }

    /**
     * Removes a header
     * 
     * @param name
     *            The header name
     */
    public void removeHeader(String name) {
        mHeaders.remove(name);
    }

    /**
     * Sets the request HTTP verb
     * @param httpVerb Http Verb
     */
    public void setVerb(String httpVerb) {
        mVerb = httpVerb;
    }

    /**
     * Returns the request HTTP verb
     * @return String Verb
     */
    public String getVerb() {
        return mVerb;
    }

    /**
     * Sets the request URL
     * @param url URL
     */
    public void setUrl(String url) {
        mUrl = url;
    }

    /**
     * Returns the request URL
     * @return String URL
     */
    public String getUrl() {
        return mUrl;
    }

    /**
     * Logs the request data
     * 
     * @param logger
     *            the provided logger
     */
    public void log(Logger logger) {
        if (logger != null) {
            logger.log("URL: " + getUrl(), LogLevel.Verbose);
            logger.log("VERB: " + getVerb(), LogLevel.Verbose);

            for (String key : mHeaders.keySet()) {
                logger.log("Header " + key + ": " + mHeaders.get(key), LogLevel.Verbose);
            }
            logger.log("CONTENT: " + getContent(), LogLevel.Verbose);
        }
    }
}

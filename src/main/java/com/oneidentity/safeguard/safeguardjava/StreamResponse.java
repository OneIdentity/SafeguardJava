package com.oneidentity.safeguard.safeguardjava;

import com.oneidentity.safeguard.safeguardjava.exceptions.SafeguardForJavaException;
import java.io.IOException;
import java.io.InputStream;
import org.apache.http.client.methods.CloseableHttpResponse;

/** 
 * Represents a streamed response
 */
public class StreamResponse {
    private boolean disposed;

    public StreamResponse(CloseableHttpResponse resp) {
        response = resp;
    }

    private final CloseableHttpResponse response;
    private InputStream stream = null;
    private Long contentLength = 0L;

    /**
     * Get the response stream object
     *
     * @return The HTTP response body content as an inputstream
     */
    public InputStream getStream() throws SafeguardForJavaException
    {
        if (stream == null) {
            try {
                stream = response.getEntity().getContent();
            } catch (Exception ex) {
                throw new SafeguardForJavaException("Unable to read the download stream", ex);
            }
        }
        return stream;
    }

    /**
     * Get the response content length
     *
     * @return The HTTP response body content length
     */
    public Long getContentLength() {
        if (contentLength == 0) {
            contentLength = response.getEntity().getContentLength();
        }
        return contentLength;
    }
    
    public void dispose() {
        if (!disposed) {
            disposed = true;
            if (stream != null) {
                try { 
                    stream.close(); 
                } catch (IOException logOrIgnore) {}
            }
        }
    }
}

package com.oneidentity.safeguard.safeguardjava.restclient;

import com.oneidentity.safeguard.safeguardjava.IProgressCallback;
import java.io.IOException;
import java.io.OutputStream;

public class ByteArrayEntity extends org.apache.http.entity.ByteArrayEntity {
    
    private OutputStreamProgress outstream;
    private final IProgressCallback progressCallback;
    private final long totalBytes;

    public ByteArrayEntity(byte[] b, IProgressCallback progressCallback) {
        super(b);
        this.progressCallback = progressCallback;
        this.totalBytes = b.length;
    }

    @Override
    public void writeTo(OutputStream outstream) throws IOException {
        this.outstream = new OutputStreamProgress(outstream, this.progressCallback, totalBytes);
        super.writeTo(this.outstream);
    }

    public int getProgress() {
        if (outstream == null) {
            return 0;
        }
        long contentLength = getContentLength();
        if (contentLength <= 0) { // Prevent division by zero and negative values
            return 0;
        }
        long writtenLength = outstream.getWrittenLength();
        return (int) (100*writtenLength/contentLength);
    }    
}

/*
Copyright (c) Microsoft Open Technologies, Inc.
All Rights Reserved
See License.txt in the project root for license information.
*/

package microsoft.aspnet.signalr.client.http;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import microsoft.aspnet.signalr.client.Constants;

/**
 * Response implementation based on an InputStream
 */
public class StreamResponse implements Response {
    private BufferedReader mReader;
    private int mStatus;
    private InputStream mOriginalStream;
    Map<String, List<String>> mHeaders;

    /**
     * Initializes the StreamResponse
     * 
     * @param stream
     *            stream to read
     * @param status
     *            HTTP status code
     * @param headers Headers
     */
    public StreamResponse(InputStream stream, int status, Map<String, List<String>> headers) {
        mOriginalStream = stream;
        mReader = new BufferedReader(new InputStreamReader(mOriginalStream, Constants.UTF8));
        mHeaders = new HashMap<>(headers);
        mStatus = status;
    }

    @Override
    public byte[] readAllBytes() throws IOException {
        List<Byte> bytes = new ArrayList<>();

        int bufferSize = 1024;
        byte[] buffer = new byte[bufferSize];

        int bytesRead = mOriginalStream.read(buffer, 0, bufferSize);
        while (bytesRead != -1) {
            for (int i = 0; i < bytesRead; i++) {
                bytes.add(buffer[i]);
            }

            bytesRead = mOriginalStream.read(buffer, 0, bufferSize);
        }

        byte[] byteArray = new byte[bytes.size()];

        for (int i = 0; i < bytes.size(); i++) {
            byteArray[i] = bytes.get(i).byteValue();
        }

        return byteArray;
    }

    @Override
    public String readToEnd() throws IOException {
        StringBuilder sb = new StringBuilder();
        String line = null;
        while ((line = mReader.readLine()) != null) {
            sb.append(line);
            sb.append("\n");
        }

        return sb.toString();
    }

    @Override
    public int getStatus() {
        return mStatus;
    }

    @Override
    public String readLine() throws IOException {
        return mReader.readLine();
    }

    @Override
    public Map<String, List<String>> getHeaders() {
        return new HashMap<>(mHeaders);
    }

    @Override
    public List<String> getHeader(String headerName) {
        return mHeaders.get(headerName);
    }
}

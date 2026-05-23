package com.oneidentity.safeguard.safeguardjava.restclient;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.oneidentity.safeguard.safeguardjava.exceptions.ResponseTooLargeException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okio.Buffer;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.HttpEntity;
import org.apache.hc.core5.http.io.entity.BasicHttpEntity;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * Regression test for FP-SafeguardJava-004 (W5 — response-body size cap).
 *
 * <p>Three scenarios:
 * <ol>
 *   <li><b>Content-Length lie:</b> server advertises a 200 MB Content-Length
 *       header but the body is 10 bytes. {@link BoundedResponseReader} must
 *       throw {@link ResponseTooLargeException} from the pre-read header
 *       check, before any body bytes are consumed.</li>
 *   <li><b>Chunked overflow:</b> server streams a chunked body with no
 *       Content-Length; the test caps the reader at 256 KiB and supplies
 *       512 KiB of body so the streaming counter trips mid-read.</li>
 *   <li><b>Within cap (happy path):</b> small body returns intact.</li>
 * </ol>
 *
 * <p>No live appliance is needed for this test: the attacker scenario
 * cannot be reproduced against a real Safeguard. Tag: {@code appliance:
 * not-required}.
 */
public class RestClientResponseSizeCapTest {

    private MockWebServer server;
    private CloseableHttpClient client;

    @Before
    public void setUp() throws IOException {
        server = new MockWebServer();
        server.start();
        client = HttpClients.createDefault();
    }

    @After
    public void tearDown() throws IOException {
        try {
            client.close();
        } finally {
            server.shutdown();
        }
    }

    @Test
    public void contentLengthLieIsRejectedBeforeReadingBody() throws Exception {
        // Construct a synthetic entity whose Content-Length advertises 200 MB but
        // whose body is 10 bytes. Going through the network is unreliable here
        // because servers/clients often normalize Content-Length to match the
        // actual payload; the pre-read header check operates on whatever the
        // HttpEntity reports, so we exercise it directly.
        final byte[] payload = "0123456789".getBytes(StandardCharsets.UTF_8);
        final long lyingLength = 209715200L;
        HttpEntity entity = new BasicHttpEntity(
                new ByteArrayInputStream(payload),
                lyingLength,
                ContentType.APPLICATION_OCTET_STREAM);

        try {
            BoundedResponseReader.readBodyAsString(entity);
            fail("Expected ResponseTooLargeException from pre-read header check");
        } catch (ResponseTooLargeException ex) {
            assertTrue("Exception message should reference the lying length: " + ex.getMessage(),
                    ex.getMessage().contains(String.valueOf(lyingLength)));
        }
    }

    @Test
    public void chunkedOverflowTripsStreamingCounter() throws Exception {
        // Send 512 KiB of body via chunked transfer-encoding (no Content-Length).
        int totalBytes = 512 * 1024;
        Buffer body = new Buffer();
        byte[] chunk = new byte[1024];
        for (int i = 0; i < chunk.length; i++) {
            chunk[i] = (byte) ('A' + (i % 26));
        }
        for (int written = 0; written < totalBytes; written += chunk.length) {
            body.write(chunk);
        }
        // chunkSizeBytes > 0 forces chunked transfer-encoding
        server.enqueue(new MockResponse()
                .setResponseCode(200)
                .setChunkedBody(body, 64 * 1024));

        HttpEntity entity = getEntity("/chunked");

        int testCap = 256 * 1024;
        try {
            BoundedResponseReader.readBodyAsBytes(entity, testCap);
            fail("Expected ResponseTooLargeException during streaming");
        } catch (ResponseTooLargeException ex) {
            assertTrue("Exception message should reference the cap: " + ex.getMessage(),
                    ex.getMessage().contains(String.valueOf(testCap)));
        }
    }

    @Test
    public void smallBodyWithinCapIsReturnedIntact() throws Exception {
        String payload = "{\"ok\":true}";
        server.enqueue(new MockResponse()
                .setResponseCode(200)
                .setHeader("Content-Type", "application/json; charset=utf-8")
                .setBody(payload));

        HttpEntity entity = getEntity("/small");
        String body = BoundedResponseReader.readBodyAsString(entity);
        assertEquals(payload, body);
    }

    @Test
    public void byteArrayReadReturnsExactContent() throws Exception {
        byte[] payload = new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
        Buffer body = new Buffer();
        body.write(payload);
        server.enqueue(new MockResponse()
                .setResponseCode(200)
                .setBody(body));

        HttpEntity entity = getEntity("/bytes");
        byte[] received = BoundedResponseReader.readBodyAsBytes(entity, 1024);
        assertArrayEquals(payload, received);
    }

    @Test(expected = IllegalArgumentException.class)
    public void zeroCapIsRejected() throws Exception {
        server.enqueue(new MockResponse().setResponseCode(200).setBody("x"));
        HttpEntity entity = getEntity("/cap0");
        BoundedResponseReader.readBodyAsBytes(entity, 0);
    }

    @Test(expected = IllegalArgumentException.class)
    public void overAbsoluteMaxIsRejected() throws Exception {
        server.enqueue(new MockResponse().setResponseCode(200).setBody("x"));
        HttpEntity entity = getEntity("/capmax");
        BoundedResponseReader.readBodyAsBytes(entity, BoundedResponseReader.ABSOLUTE_MAX_BYTES + 1);
    }

    private HttpEntity getEntity(String path) throws IOException {
        URI uri = server.url(path).uri();
        HttpGet get = new HttpGet(uri);
        // Note: we deliberately leak the response here because the entity stream
        // is consumed by the reader-under-test; the test class teardown closes
        // the client which releases the connection.
        CloseableHttpResponse response = client.execute(get);
        return response.getEntity();
    }
}

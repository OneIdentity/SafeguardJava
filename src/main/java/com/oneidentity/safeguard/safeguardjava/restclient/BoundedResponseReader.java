package com.oneidentity.safeguard.safeguardjava.restclient;

import com.oneidentity.safeguard.safeguardjava.exceptions.ResponseTooLargeException;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.HttpEntity;

/**
 * Bounded reader for HTTP response bodies.
 *
 * <p>Used by the in-memory response paths ({@code Utils.getResponse}, the
 * rSTS form-post in {@code PkceAuthenticator}, and similar) to guarantee
 * that the client never allocates more than {@link #DEFAULT_MAX_BYTES}
 * (10 MB) for a single response. A misbehaving or malicious appliance can
 * advertise a huge {@code Content-Length} or send an unbounded chunked
 * stream; either case is rejected here with a
 * {@link ResponseTooLargeException} before the client OOMs.
 *
 * <p>Two paths are enforced:
 * <ol>
 *   <li><b>Pre-read header check.</b> If the entity exposes a
 *       {@code Content-Length} greater than the cap, throw immediately
 *       without touching the body stream.</li>
 *   <li><b>Streaming counter.</b> If no Content-Length is advertised
 *       (chunked transfer-encoding) or the advertised length is a lie,
 *       read in 8 KiB chunks and throw as soon as the running byte count
 *       exceeds the cap.</li>
 * </ol>
 *
 * <p>This cap applies only to in-memory buffering paths. The explicit
 * streaming download API ({@code StreamResponse} / {@code StreamingRequest})
 * is unaffected; callers there manage their own sinks (typically a file).
 */
public final class BoundedResponseReader {

    /** 10 MB. Larger than any normal Safeguard JSON response, small enough to bound OOM risk. */
    public static final int DEFAULT_MAX_BYTES = 10 * 1024 * 1024;

    /** Hard maximum the cap may ever be raised to. */
    public static final int ABSOLUTE_MAX_BYTES = 100 * 1024 * 1024;

    private static final int CHUNK_SIZE = 8 * 1024;

    private BoundedResponseReader() {}

    /** Read the entity body, decoding with the entity's declared charset (default UTF-8). */
    public static String readBodyAsString(HttpEntity entity) throws IOException, ResponseTooLargeException {
        return readBodyAsString(entity, DEFAULT_MAX_BYTES);
    }

    public static String readBodyAsString(HttpEntity entity, int maxBytes)
            throws IOException, ResponseTooLargeException {
        byte[] bytes = readBodyAsBytes(entity, maxBytes);
        if (bytes == null) {
            return null;
        }
        Charset charset = StandardCharsets.UTF_8;
        try {
            ContentType ct = ContentType.parse(entity.getContentType());
            if (ct != null && ct.getCharset() != null) {
                charset = ct.getCharset();
            }
        } catch (RuntimeException ignored) {
            // Malformed Content-Type header -> default to UTF-8
        }
        return new String(bytes, charset);
    }

    /** Read the entity body as raw bytes, with the size cap enforced both pre-read and during streaming. */
    public static byte[] readBodyAsBytes(HttpEntity entity, int maxBytes)
            throws IOException, ResponseTooLargeException {
        if (entity == null) {
            return null;
        }
        if (maxBytes <= 0 || maxBytes > ABSOLUTE_MAX_BYTES) {
            throw new IllegalArgumentException(
                    "maxBytes must be in (0, " + ABSOLUTE_MAX_BYTES + "]");
        }

        long declaredLength = entity.getContentLength();
        if (declaredLength > maxBytes) {
            throw new ResponseTooLargeException(declaredLength, maxBytes);
        }

        long total = 0L;
        ByteArrayOutputStream buf = new ByteArrayOutputStream(
                declaredLength > 0 ? (int) Math.min(declaredLength, CHUNK_SIZE) : CHUNK_SIZE);
        try (InputStream in = entity.getContent()) {
            if (in == null) {
                return null;
            }
            byte[] chunk = new byte[CHUNK_SIZE];
            int n;
            while ((n = in.read(chunk)) != -1) {
                total += n;
                if (total > maxBytes) {
                    throw new ResponseTooLargeException(total, maxBytes);
                }
                buf.write(chunk, 0, n);
            }
        }
        return buf.toByteArray();
    }
}

package com.oneidentity.safeguard.safeguardjava;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.oneidentity.safeguard.safeguardjava.exceptions.ResponseTooLargeException;
import com.oneidentity.safeguard.safeguardjava.exceptions.SafeguardForJavaException;
import com.oneidentity.safeguard.safeguardjava.restclient.BoundedResponseReader;
import java.io.IOException;
import java.security.Provider;
import java.security.Security;
import java.util.HashMap;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.apache.hc.core5.http.HttpEntity;
import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;

public class Utils {

    private static final Logger logger = LoggerFactory.getLogger(Utils.class);

    private static String OS = null;

    private Utils() {
    }

    public static boolean isNullOrEmpty(String param) {
        return param == null || param.trim().length() == 0;
    }

    public static String toJsonString(String name, Object value, boolean prependSep) {
        if (value != null) {
            return (prependSep ? ", " : "") + "\"" + name + "\" : " + (value instanceof String ? "\"" + value.toString() + "\"" : value.toString());
        }
        return "";
    }

    public static Map<String, String> parseResponse(String response) {

        ObjectMapper mapper = new ObjectMapper();
        Map<String, String> map = new HashMap<>();
        try {
            map = mapper.readValue(response, new TypeReference<Map<String, String>>() {
            });
        } catch (IOException ex) {
            logger.error("Exception occurred", ex);
        }

        return map;
    }

    /**
     * Read the response body as a String, capped at
     * {@link BoundedResponseReader#DEFAULT_MAX_BYTES} (10 MB).
     *
     * <p>The cap defends against a misbehaving or malicious appliance
     * advertising a huge Content-Length or sending an unbounded chunked
     * stream that would otherwise OOM the client.
     *
     * @throws SafeguardForJavaException if the body exceeds the cap
     *         (as {@link ResponseTooLargeException}). I/O errors during
     *         body read are swallowed for backwards compatibility, matching
     *         the prior behaviour of this helper.
     */
    public static String getResponse(CloseableHttpResponse response) throws SafeguardForJavaException {
        HttpEntity entity = response.getEntity();
        if (entity != null) {
            try {
                String body = BoundedResponseReader.readBodyAsString(entity);
                return body != null ? body : "";
            } catch (ResponseTooLargeException ex) {
                throw ex;
            } catch (IOException ex) {
                logger.warn("Failed to read response body", ex);
            }
        }
        return "";
    }

    public static boolean isSuccessful(int status) {
        switch (status) {
            case 200:
            case 201:
            case 202:
            case 204:
                return true;
            default:
                return false;
        }
    }

    public static String getOsName() {
        if (OS == null) {
            OS = System.getProperty("os.name");
        }
        return OS;
    }

    public static boolean isWindows() {
        return getOsName().startsWith("Windows");
    }

    public static boolean isSunMSCAPILoaded() {
        Provider provider = Security.getProvider("SunMSCAPI");
        return provider != null;
    }

}

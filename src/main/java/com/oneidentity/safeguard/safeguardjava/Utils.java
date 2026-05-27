package com.oneidentity.safeguard.safeguardjava;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.security.Provider;
import java.security.Security;
import java.util.HashMap;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.apache.hc.core5.http.HttpEntity;
import org.apache.hc.core5.http.ParseException;
import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;
import org.apache.hc.core5.http.io.entity.EntityUtils;

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

    public static String getResponse(CloseableHttpResponse response) {
        HttpEntity entity = response.getEntity();
        if (entity != null) {
            try {
                return EntityUtils.toString(response.getEntity());

            } catch (IOException | ParseException ex) {}
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

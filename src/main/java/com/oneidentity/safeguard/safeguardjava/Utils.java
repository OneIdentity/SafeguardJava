package com.oneidentity.safeguard.safeguardjava;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.oneidentity.safeguard.safeguardjava.authentication.PasswordAuthenticator;
import com.oneidentity.safeguard.safeguardjava.classloader.SafeguardClassLoader;
import com.oneidentity.safeguard.safeguardjava.exceptions.SafeguardForJavaException;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.ws.rs.core.Response;

public class Utils {

    private Utils() {
    }
    
    public static boolean isNullOrEmpty(String param) {
        return param == null || param.trim().length() == 0;
    }
    
    public static String toJsonString (String name, Object value, boolean prependSep) {
        if (value != null) {
            return (prependSep ? ", " : "") + "\"" + name + "\" : " + (value instanceof String ? "\"" + value.toString() + "\"" : value.toString());
        }
        return "";
    }

    public static Map<String,String> parseResponse(Response response) {
        String resp = response.readEntity(String.class);
        
        ObjectMapper mapper = new ObjectMapper();
        Map<String,String> map = new HashMap<>();
        try {
            map = mapper.readValue(resp, new TypeReference<Map<String,String>>(){});
        } catch (IOException ex) {
            Logger.getLogger(PasswordAuthenticator.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        return map;
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
    
    public static ClassLoader setClassLoader() throws SafeguardForJavaException {
        URL u = null;
        ClassLoader cl = Thread.currentThread().getContextClassLoader();
        try {
            String f = Safeguard.class.getProtectionDomain().getCodeSource().getLocation().getPath();
            while (f.startsWith("/")) {
                f = f.substring(1);
            }
            u = new URL("file://"+f);
        } catch (MalformedURLException ex) {
            throw new SafeguardForJavaException("Failed to load the SafeguardClassLoader " + ex.getMessage());
        }
        Thread.currentThread().setContextClassLoader(SafeguardClassLoader.getInstance(new URL[]{u}));
        
        return cl;
    }
    
    public static void restoreClassLoader(ClassLoader classLoader) {
        Thread.currentThread().setContextClassLoader(classLoader);
    }
    
}

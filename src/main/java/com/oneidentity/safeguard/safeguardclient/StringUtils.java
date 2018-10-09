package com.oneidentity.safeguard.safeguardclient;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.oneidentity.safeguard.safeguardclient.authentication.PasswordAuthenticator;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.ws.rs.core.Response;

public class StringUtils {

    private StringUtils() {
    }
    
    public static boolean isNullOrEmpty(String param) {
        return param == null || param.trim().length() == 0;
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
    
    
}

package com.oneidentity.safeguard.safeguardjava.data;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;
import com.oneidentity.safeguard.safeguardjava.exceptions.SafeguardForJavaException;
import java.util.logging.Level;
import java.util.logging.Logger;

public class JoinRequest implements JsonObject {

    private String spp;
    private char[] spp_api_token;
    private String spp_cert_chain;

    public JoinRequest() {
    }
      
    public String getSpp() {
        return spp;
    }

    public void setSpp(String spp) {
        this.spp = spp;
    }

    public char[] getSpp_api_token() {
        return spp_api_token;
    }

    public void setSpp_api_token(char[] spp_api_token) {
        this.spp_api_token = spp_api_token;
    }

    public String getSpp_cert_chain() {
        return spp_cert_chain;
    }

    public void setSpp_cert_chain(String spp_cert_chain) {
        this.spp_cert_chain = spp_cert_chain;
    }
    
    @Override
    public String toJson() throws SafeguardForJavaException {
        ObjectWriter ow = new ObjectMapper().writer().withDefaultPrettyPrinter();
        try {
            return ow.writeValueAsString(this);
        } catch (JsonProcessingException ex) {
            Logger.getLogger(JoinRequest.class.getName()).log(Level.FINEST, null, ex);
            throw new SafeguardForJavaException("Failed to convert request to json", ex);
        }
    }
    
}

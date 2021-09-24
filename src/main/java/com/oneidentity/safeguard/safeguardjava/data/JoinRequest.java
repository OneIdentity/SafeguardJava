package com.oneidentity.safeguard.safeguardjava.data;

import com.oneidentity.safeguard.safeguardjava.Utils;

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
    public String toJson() {
        return new StringBuffer("{")
                .append(Utils.toJsonString("spp", this.spp, false))
                .append(Utils.toJsonString("spp_api_token", this.spp_api_token.toString(), true))
                .append(Utils.toJsonString("spp_cert_chain", this.spp_cert_chain, true))
                .append("}").toString();
    }
    
}

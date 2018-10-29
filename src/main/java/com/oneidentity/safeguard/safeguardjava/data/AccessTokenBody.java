package com.oneidentity.safeguard.safeguardjava.data;

public class AccessTokenBody {
    
    private final char[] stsAccessToken;

    public AccessTokenBody(char[] stsAccessToken ) {
        this.stsAccessToken = stsAccessToken;
    }

    @Override
    public String toString() {
        return new StringBuffer("{ \"StsAccessToken\" : \"")
                .append(new String(this.stsAccessToken))
                .append("\"}").toString();
    }    
}

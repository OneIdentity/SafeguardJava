package com.oneidentity.safeguard.safeguardjava.data;

import com.oneidentity.safeguard.safeguardjava.StringUtils;

public class AccessTokenBody implements JsonObject {
    
    private final char[] stsAccessToken;

    public AccessTokenBody(char[] stsAccessToken ) {
        this.stsAccessToken = stsAccessToken;
    }

    @Override
    public String toJson() {
        return new StringBuffer("{")
                .append(StringUtils.toJsonString("StsAccessToken", new String(this.stsAccessToken), false))
                .append("}").toString();
    }
}

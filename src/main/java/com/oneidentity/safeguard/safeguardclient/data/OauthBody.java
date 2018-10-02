package com.oneidentity.safeguard.safeguardclient.data;

public class OauthBody {
    
    private String grantType;
    private String username;
    private char[] password;
    private String scope;
    private final boolean isPassword;

    public OauthBody(String grantType, String username, char[] password, String scope ) {
        this.grantType = grantType;
        this.username = username;
        this.password = password.clone();
        this.scope = scope;
        this.isPassword = true;
    }
    
    public OauthBody(String grantType, String scope ) {
        this.grantType = grantType;
        this.username = null;
        this.password = null;
        this.scope = scope;
        this.isPassword = false;
    }

    
    public String getGrantType() {
        return grantType;
    }

    public void setGrantType(String grantType) {
        this.grantType = grantType;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public char[] getPassword() {
        return password;
    }

    public void setPassword(char[] password) {
        this.password = password;
    }

    public String getScope() {
        return scope;
    }

    public void setScope(String scope) {
        this.scope = scope;
    }
    
    @Override
    public String toString() {
        if (isPassword) {
            return new StringBuffer("{ \"grant_type\" : \"").append(this.grantType)
                    .append("\", \"username\" : \"").append(this.username)
                    .append("\", \"password\" : \"").append(new String(this.password))
                    .append("\", \"scope\" : \"").append(this.scope)
                    .append("\"}").toString();
        }
        else {
            return new StringBuffer("{ \"grant_type\" : \"").append(this.grantType)
                    .append("\", \"scope\" : \"").append(this.scope)
                    .append("\"}").toString();
        }
    }    
}

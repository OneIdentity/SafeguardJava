package com.oneidentity.safeguard.safeguardjava.data;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.oneidentity.safeguard.safeguardjava.IApiKeySecret;


/**
 * This class is used to get the API key secret.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class ApiKeySecret extends ApiKeySecretBase implements IApiKeySecret {
    
    @JsonProperty("ClientSecret")
    private char[] clientSecret;

    public ApiKeySecret() {
    }

    @Override
    public char[] getClientSecret() {
        return clientSecret;
    }

    public void setClientSecret(char[] clientSecret) {
        this.clientSecret = clientSecret;
    }
}

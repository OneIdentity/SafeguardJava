package com.oneidentity.safeguard.safeguardjava.data;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;


/**
 * This class is used to get the API key secret.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class ApiKeySecretInternal extends ApiKeySecretBase {
    
    @JsonProperty("ClientSecret")
    private String clientSecret;

    public ApiKeySecretInternal() {
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public void setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
    }
}

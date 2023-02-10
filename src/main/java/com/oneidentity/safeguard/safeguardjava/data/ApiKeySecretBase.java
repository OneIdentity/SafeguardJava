package com.oneidentity.safeguard.safeguardjava.data;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;


/**
 * This class is used to get the API key secret.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
class ApiKeySecretBase {
    
    @JsonProperty("Id")
    private Integer id;
    @JsonProperty("Name")
    private String name;
    @JsonProperty("Description")
    private String description;
    @JsonProperty("ClientId")
    private String clientId;
    @JsonProperty("ClientSecretId")
    private String clientSecretId;

    public ApiKeySecretBase() {
    }

    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getClientSecretId() {
        return clientSecretId;
    }

    public void setClientSecretId(String clientSecretId) {
        this.clientSecretId = clientSecretId;
    }

}

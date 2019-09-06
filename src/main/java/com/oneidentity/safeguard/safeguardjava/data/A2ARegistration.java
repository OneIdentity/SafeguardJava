package com.oneidentity.safeguard.safeguardjava.data;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * This class is used to get the A2A registrations.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class A2ARegistration {
    
    @JsonProperty("Id")
    private Integer id;
    @JsonProperty("AppName")
    private String appName;
    @JsonProperty("Description")
    private String description;
    @JsonProperty("Disabled")
    private boolean disabled;

    public A2ARegistration() {
    }

    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public String getAppName() {
        return appName;
    }

    public void setAppName(String appName) {
        this.appName = appName;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public boolean isDisabled() {
        return disabled;
    }

    public void setDisabled(boolean disabled) {
        this.disabled = disabled;
    }
}

package com.oneidentity.safeguard.safeguardclient.data;

import com.fasterxml.jackson.annotation.JsonProperty;

public class SafeguardApplianceStatus {
    @JsonProperty("Identity")
    private String Identity;
    @JsonProperty("Name")
    private String Name;

    public String getIdentity() {
        return Identity;
    }

    public void setIdentity(String Identity) {
        this.Identity = Identity;
    }

    public String getName() {
        return Name;
    }

    public void setName(String Name) {
        this.Name = Name;
    }
    
}

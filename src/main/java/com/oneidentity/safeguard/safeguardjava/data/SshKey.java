package com.oneidentity.safeguard.safeguardjava.data;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * This class is used to set the SshKey.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class SshKey {
    
    @JsonProperty("Passphrase")
    private String passphrase;
    @JsonProperty("PrivateKey")
    private String privateKey;

    public SshKey() {
    }

    public String getPassphrase() {
        return passphrase;
    }

    public void setPassphrase(String passphrase) {
        this.passphrase = passphrase;
    }

    public String getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(String privateKey) {
        this.privateKey = privateKey;
    }
}

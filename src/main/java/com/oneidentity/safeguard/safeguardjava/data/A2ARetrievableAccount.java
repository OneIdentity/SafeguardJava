package com.oneidentity.safeguard.safeguardjava.data;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Arrays;

/**
 * This class is used to get the retrievable accounts for an A2A registration.
 */
@JsonIgnoreProperties
public class A2ARetrievableAccount {
    private boolean disposed;

    private String applicationName;
    private String description;
    @JsonProperty("AccountDisabled")
    private boolean disabled;
    @JsonProperty("ApiKey")
    private char[] apiKey;
    @JsonProperty("SystemId")
    private int assetId;
    @JsonProperty("SystemName")
    private String assetName;
    @JsonProperty("AssetDescription")
    private String assetDescription;
    @JsonProperty("AccountId")
    private int accountId;
    @JsonProperty("AccountName")
    private String accountName;
    @JsonProperty("DomainName")
    private String domainName;
    @JsonProperty("AccountType")
    private String accountType;
    @JsonProperty("AccountDescription")
    private String accountDescription;

    public String getApplicationName() {
        return applicationName;
    }

    public void setApplicationName(String applicationName) {
        this.applicationName = applicationName;
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

    public char[] getApiKey() {
        return apiKey;
    }

    public void setApiKey(char[] apiKey) {
        this.apiKey = apiKey;
    }

    public int getAssetId() {
        return assetId;
    }

    public void setAssetId(int assetId) {
        this.assetId = assetId;
    }

    public String getAssetName() {
        return assetName;
    }

    public void setAssetName(String assetName) {
        this.assetName = assetName;
    }

    public int getAccountId() {
        return accountId;
    }

    public void setAccountId(int accountId) {
        this.accountId = accountId;
    }

    public String getAccountName() {
        return accountName;
    }

    public void setAccountName(String accountName) {
        this.accountName = accountName;
    }

    public String getDomainName() {
        return domainName;
    }

    public void setDomainName(String domainName) {
        this.domainName = domainName;
    }

    public String getAccountType() {
        return accountType;
    }

    public void setAccountType(String accountType) {
        this.accountType = accountType;
    }
    
    public String getAssetDescription() {
        return assetDescription;
    }

    public void setAssetDescription(String assetDescription) {
        this.assetDescription = assetDescription;
    }

    public String getAccountDescription() {
        return accountDescription;
    }

    public void setAccountDescription(String accountDescription) {
        this.accountDescription = accountDescription;
    }

    public void dispose()
    {
        if (apiKey != null) {
            Arrays.fill(apiKey, '0');
        }
        disposed = true;
        apiKey = null;
    }
    
    @Override
    protected void finalize() throws Throwable {
        try {
            if (apiKey != null) {
                Arrays.fill(apiKey, '0');
            }
        } finally {
            disposed = true;
            super.finalize();
        }
    }
}

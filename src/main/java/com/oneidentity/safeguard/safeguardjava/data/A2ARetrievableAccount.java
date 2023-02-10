package com.oneidentity.safeguard.safeguardjava.data;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.oneidentity.safeguard.safeguardjava.IA2ARetrievableAccount;
import java.util.Arrays;

/**
 * This class is used to get the retrievable accounts for an A2A registration.
 */
@JsonIgnoreProperties
public class A2ARetrievableAccount implements IA2ARetrievableAccount {
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
    @JsonProperty("AssetNetworkAddress")
    private String assetNetworkAddress;
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

    @Override
    public String getApplicationName() {
        return applicationName;
    }

    public void setApplicationName(String applicationName) {
        this.applicationName = applicationName;
    }

    @Override
    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    @Override
    public boolean isDisabled() {
        return disabled;
    }

    public void setDisabled(boolean disabled) {
        this.disabled = disabled;
    }

    @Override
    public char[] getApiKey() {
        return apiKey;
    }

    public void setApiKey(char[] apiKey) {
        this.apiKey = apiKey;
    }

    @Override
    public int getAssetId() {
        return assetId;
    }

    public void setAssetId(int assetId) {
        this.assetId = assetId;
    }

    @Override
    public String getAssetName() {
        return assetName;
    }

    public void setAssetName(String assetName) {
        this.assetName = assetName;
    }

    @Override
    public String getAssetNetworkAddress() {
        return assetNetworkAddress;
    }

    public void setAssetNetworkAddress(String assetNetworkAddress) {
        this.assetNetworkAddress = assetNetworkAddress;
    }
    
    @Override
    public int getAccountId() {
        return accountId;
    }

    public void setAccountId(int accountId) {
        this.accountId = accountId;
    }

    @Override
    public String getAccountName() {
        return accountName;
    }

    public void setAccountName(String accountName) {
        this.accountName = accountName;
    }

    @Override
    public String getDomainName() {
        return domainName;
    }

    public void setDomainName(String domainName) {
        this.domainName = domainName;
    }

    @Override
    public String getAccountType() {
        return accountType;
    }

    public void setAccountType(String accountType) {
        this.accountType = accountType;
    }
    
    @Override
    public String getAssetDescription() {
        return assetDescription;
    }

    public void setAssetDescription(String assetDescription) {
        this.assetDescription = assetDescription;
    }

    @Override
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

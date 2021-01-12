package com.oneidentity.safeguard.safeguardjava.data;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;


@JsonIgnoreProperties(ignoreUnknown = true)
public class A2ARetrievableAccountInternal {

    @JsonProperty("AccountDisabled")
    private boolean accountDisabled;
    @JsonProperty("ApiKey")
    private String apiKey;
    @JsonProperty("SystemId")
    private int systemId;
    @JsonProperty("SystemName")
    private String systemName;
    @JsonProperty("AccountId")
    private int accountId;
    @JsonProperty("AccountName")
    private String accountName;
    @JsonProperty("DomainName")
    private String domainName;
    @JsonProperty("AccountType")
    private String accountType;
    @JsonProperty("SystemDescription")
    private String assetDescription;
    @JsonProperty("AccountDescription")
    private String accountDescription;
    @JsonProperty("NetworkAddress")
    private String assetNetworkAddress;

    public A2ARetrievableAccountInternal() {
    }

    public boolean isAccountDisabled() {
        return accountDisabled;
    }

    public void setAccountDisabled(boolean accountDisabled) {
        this.accountDisabled = accountDisabled;
    }

    public String getApiKey() {
        return apiKey;
    }

    public void setApiKey(String apiKey) {
        this.apiKey = apiKey;
    }

    public int getSystemId() {
        return systemId;
    }

    public void setSystemId(int systemId) {
        this.systemId = systemId;
    }

    public String getSystemName() {
        return systemName;
    }

    public void setSystemName(String systemName) {
        this.systemName = systemName;
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
    
    public String getAssetNetworkAddress() {
        return assetNetworkAddress;
    }

    public void setAssetNetworkAddress(String assetNetworkAddress) {
        this.assetNetworkAddress = assetNetworkAddress;
    }
}

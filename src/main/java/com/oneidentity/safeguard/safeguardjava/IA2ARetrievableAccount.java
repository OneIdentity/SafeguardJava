package com.oneidentity.safeguard.safeguardjava;

/**
 * Represents an A2A retrievable account
 */
public interface IA2ARetrievableAccount {

    /**
     * Get the application name
     * @return String
     */
    String getApplicationName();

    /**
     * Get the description
     * @return String
     */
    String getDescription();

    /**
     * Is the account disabled
     * @return boolean
     */
    boolean isDisabled();

    /**
     * Get the A2A API key
     * @return char[]
     */
    char[] getApiKey();

    /**
     * Get the asset Id
     * @return int
     */
    int getAssetId();

    /**
     * Get the asset name
     * @return String
     */
    String getAssetName();

    /**
     * Get the asset network address 
     * @return String
     */
    String getAssetNetworkAddress();

    /**
     * Get the account Id
     * @return int
     */
    int getAccountId();

    /**
     * Get the account name
     * @return String
     */
    String getAccountName();

    /**
     * Get the domain name
     * @return String
     */
    String getDomainName();

    /**
     * Get the account type
     * @return String
     */
    String getAccountType();

    /**
     * Get the asset description
     * @return String
     */
    String getAssetDescription();

    /**
     * Get the account description
     * @return String
     */
    String getAccountDescription();
}

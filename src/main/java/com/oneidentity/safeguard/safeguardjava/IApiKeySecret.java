package com.oneidentity.safeguard.safeguardjava;

/**
 * Represents the Api key secret
 */
public interface IApiKeySecret {

    /**
     * Get the API key Id
     * @return Integer
     */
    Integer getId();

    /**
     * Get the API key name
     * @return String
     */
    String getName();

    /**
     * Get the API key description
     * @return String
     */
    String getDescription();

    /**
     * Get the API key client Id
     * @return String
     */
    String getClientId();

    /**
     * Get the API key client secret
     * @return char[]
     */
    char[] getClientSecret();

    /**
     * Get the API key client secret Id
     * @return String
     */
    String getClientSecretId();
}

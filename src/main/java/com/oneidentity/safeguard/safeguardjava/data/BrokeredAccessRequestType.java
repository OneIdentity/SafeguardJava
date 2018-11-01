package com.oneidentity.safeguard.safeguardjava.data;

/**
 * Type of brokered access request to create.
 */
public enum BrokeredAccessRequestType
{
    /**
     * Access request is for a password.
     */
    Password,
    /**
     * Access request is for an SSH session.
     */
    Ssh,
    /**
     * Access request is for a remote desktop session.
     */
    Rdp
}


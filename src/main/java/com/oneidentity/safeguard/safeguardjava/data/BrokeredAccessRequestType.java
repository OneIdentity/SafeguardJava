package com.oneidentity.safeguard.safeguardjava.data;

/**
 * Type of brokered access request to create.
 */
public enum BrokeredAccessRequestType
{
    /**
     * Access request is for a password.
     */
    Password ("Password"),
    /**
     * Access request is for an SSH session.
     */
    Ssh ("SSH"),
    /**
     * Access request is for a remote desktop session.
     */
    Rdp ("RemoteDesktop");
    
    private final String name;
    
    private BrokeredAccessRequestType(String s) {
        name = s;
    }
    
    public boolean equalsName (String otherName) {
        return name.equals(otherName);
    }
    
    @Override
    public String toString() {
        return this.name;
    }
}


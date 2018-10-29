package com.oneidentity.safeguard.safeguardjava.data;

/**
 * Service identifiers for the different services in the Safeguard API.
 */
public enum Service {
    /**
     * The core service contains all general cluster-wide Safeguard operations.
     */
    Core,
    
    /**
     * The appliance service contains appliance-specific Safeguard operations.
     */
    Appliance,
    
    /**
     * The notification service contains unauthenticated Safeguard operations.
     */
    Notification,
    
    /**
     * The a2a service contains application integration Safeguard operations.  It is called via the Safeguard.A2A class.
     */
    A2A
}

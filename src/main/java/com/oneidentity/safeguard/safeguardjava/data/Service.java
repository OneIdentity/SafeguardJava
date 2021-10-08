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
    A2A,
    
    /**
     * The Management service contains unauthenticated endpoints for disaster-recovery and support operations. On hardware
     * it is bound to the MGMT network interface. For on-prem VM it is unavailable except through the Kiosk app. On cloud
     * VM it is listening on port 9337 and should be firewalled appropriately to restrict access.
     */
    Management    
}

package com.oneidentity.safeguard.safeguardclient.data;

/// <summary>
/// Service identifiers for the different services in the Safeguard API.
/// </summary>
public enum Service {
    /// <summary>
    /// The core service contains all general cluster-wide Safeguard operations.
    /// </summary>
    Core,
    /// <summary>
    /// The appliance service contains appliance-specific Safeguard operations.
    /// </summary>
    Appliance,
    /// <summary>
    /// The notification service contains unauthenticated Safeguard operations.
    /// </summary>
    Notification,
    /// <summary>
    /// The a2a service contains application integration Safeguard operations.  It is called via the Safeguard.A2A class.
    /// </summary>
    A2A
    
}

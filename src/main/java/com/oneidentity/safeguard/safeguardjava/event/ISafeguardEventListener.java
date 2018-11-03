package com.oneidentity.safeguard.safeguardjava.event;

/// <summary>

import com.oneidentity.safeguard.safeguardjava.exceptions.ObjectDisposedException;
import com.oneidentity.safeguard.safeguardjava.exceptions.SafeguardEventListenerDisconnectedException;
import com.oneidentity.safeguard.safeguardjava.exceptions.SafeguardForJavaException;

/// This is an event listener interface that will allow you to be notified each time something
/// changes on Safeguard. The events that you are notified for depend on the role and event
/// registrations of the authenticated user. Safeguard event listeners use SignalR to make
/// long-lived connections to Safeguard.
/// </summary>
public interface ISafeguardEventListener
{
    /// <summary>
    /// Register an event handler to be called each time the specified event occurs. Multiple
    /// handlers may be registered for each event.
    /// </summary>
    /// <param name="eventName">Name of the event.</param>
    /// <param name="handler">Callback method.</param>
    void registerEventHandler(String eventName, SafeguardEventHandler handler) throws ObjectDisposedException;

    /// <summary>
    /// Start listening for Safeguard events in a background thread.
    /// </summary>
    void start() throws ObjectDisposedException, SafeguardForJavaException, SafeguardEventListenerDisconnectedException;

    /// <summary>
    /// Stop listening for Safeguard events in a background thread.
    /// </summary>
    void stop() throws ObjectDisposedException, SafeguardForJavaException;

    /**
     *  Disposes of the connection.
     *  
     */  
    void dispose();

}

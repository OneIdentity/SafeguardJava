package com.oneidentity.safeguard.safeguardjava.event;

/**
 * A callback that will be called when a given event occurs in Safeguard. The callback will
 * receive the event name and JSON data representing the event.
 */ 
public interface ISafeguardEventHandler {
    /**
     * Handles an incoming event
     * 
     * @param eventName Event name.
     * @param eventBody Event body.
     */
    void onEventReceived(String eventName, String eventBody);
}


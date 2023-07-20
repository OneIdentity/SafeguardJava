package com.oneidentity.safeguard.safeguardjava.event;

import com.oneidentity.safeguard.safeguardjava.data.SafeguardEventListenerState;

/**
 * A callback that will be called whenever the event listener connection state Changes.
 */ 
public interface ISafeguardEventListenerStateCallback {
    /**
     * Handles an incoming event listener connection change.
     * 
     * @param eventListenerState New connection state of the event listener.
     */
    void onEventListenerStateChange(SafeguardEventListenerState eventListenerState);
}


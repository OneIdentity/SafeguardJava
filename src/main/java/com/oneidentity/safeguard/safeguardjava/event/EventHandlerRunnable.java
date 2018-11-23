package com.oneidentity.safeguard.safeguardjava.event;

import java.util.logging.Level;
import java.util.logging.Logger;

class EventHandlerRunnable implements Runnable {

    private final ISafeguardEventHandler handler;
    private final String eventName;
    private final String eventBody;
    
    EventHandlerRunnable(ISafeguardEventHandler handler, String eventName, String eventBody) {
        this.handler = handler;
        this.eventName = eventName;
        this.eventBody = eventBody;
    }

    @Override
    public void run() {
        try
        {
            handler.onEventReceived(eventName, eventBody);
        }
        catch (Exception ex)
        {
            Logger.getLogger(EventHandlerRegistry.class.getName()).log(Level.WARNING, 
                "An error occured while calling onEventReceived");
        }
    }
}

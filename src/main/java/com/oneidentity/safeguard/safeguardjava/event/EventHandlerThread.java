package com.oneidentity.safeguard.safeguardjava.event;

abstract class EventHandlerThread extends Thread {
    
    public EventHandlerThread(Runnable eventHandlerRunnable) {
        super(eventHandlerRunnable);
    }
    
}

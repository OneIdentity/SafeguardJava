package com.oneidentity.safeguard.safeguardjava.event;

import com.oneidentity.safeguard.safeguardjava.exceptions.ObjectDisposedException;
import com.oneidentity.safeguard.safeguardjava.exceptions.SafeguardEventListenerDisconnectedException;
import com.oneidentity.safeguard.safeguardjava.exceptions.SafeguardForJavaException;

/** 
 * This is an event listener interface that will allow you to be notified each time something
 * changes on Safeguard. The events that you are notified for depend on the role and event
 * registrations of the authenticated user. Safeguard event listeners use SignalR to make
 * long-lived connections to Safeguard.
 */
public interface ISafeguardEventListener
{
    /**
     * Register an event handler to be called each time the specified event occurs. Multiple
     * handlers may be registered for each event.
     * 
     * @param eventName Name of the event.
     * @param handler Callback method.
     * @throws ObjectDisposedException Object has already been disposed
     */ 
    void registerEventHandler(String eventName, ISafeguardEventHandler handler) throws ObjectDisposedException;

    /**
     * Set an event listener callback that will be called each time the connection
     * state changes of the event listener.
     *
     * @param eventListenerStateCallback Callback method.
     */ 
    void SetEventListenerStateCallback(ISafeguardEventListenerStateCallback eventListenerStateCallback);
        
    /**
     * Start listening for Safeguard events in a background thread.
     * @throws ObjectDisposedException Object has already been disposed
     * @throws SafeguardForJavaException General Safeguard for Java exception
     * @throws SafeguardEventListenerDisconnectedException Event listener has been disconnected
     */
    void start() throws ObjectDisposedException, SafeguardForJavaException, SafeguardEventListenerDisconnectedException;

    /**
     * Stop listening for Safeguard events in a background thread.
     * 
     * @throws ObjectDisposedException Object has already been disposed
     * @throws SafeguardForJavaException General Safeguard for Java exception
     */
    void stop() throws ObjectDisposedException, SafeguardForJavaException;

    /**
     * Indicates whether the SignalR connection has completed start up.
     * 
     * @return boolean flag
     */
    boolean isStarted();

    /**
     *  Disposes of the connection.
     *  
     */  
    void dispose();

}

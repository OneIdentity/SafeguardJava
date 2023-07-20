package com.oneidentity.safeguard.safeguardjava.event;

import com.oneidentity.safeguard.safeguardjava.exceptions.ArgumentException;
import com.oneidentity.safeguard.safeguardjava.exceptions.ObjectDisposedException;
import com.oneidentity.safeguard.safeguardjava.exceptions.SafeguardForJavaException;
import java.util.logging.Level;
import java.util.logging.Logger;

public abstract class PersistentSafeguardEventListenerBase implements ISafeguardEventListener {

    private boolean disposed;

    private SafeguardEventListener eventListener;
    private final EventHandlerRegistry eventHandlerRegistry = new EventHandlerRegistry();
    private ISafeguardEventListenerStateCallback eventListenerStateCallback;

    private Thread reconnectThread = null;
    boolean isCancellationRequested = false;

    protected PersistentSafeguardEventListenerBase() {
    }

    @Override
    public void registerEventHandler(String eventName, ISafeguardEventHandler handler)
            throws ObjectDisposedException {
        if (disposed) {
            throw new ObjectDisposedException("PersistentSafeguardEventListener");
        }
        this.eventHandlerRegistry.registerEventHandler(eventName, handler);
    }

    @Override
    public void SetEventListenerStateCallback(ISafeguardEventListenerStateCallback eventListenerStateCallback)
    {
        this.eventListenerStateCallback = eventListenerStateCallback;
    }
    
    protected abstract SafeguardEventListener reconnectEventListener() throws ObjectDisposedException, SafeguardForJavaException, ArgumentException;

    class PersistentReconnectAndStartHandler implements IDisconnectHandler {

        @Override
        public void func() {
            persistentReconnectAndStart();
        }
    }

    private void persistentReconnectAndStart() {
        if (this.reconnectThread != null) {
            return;
        }

        isCancellationRequested = false;
        this.reconnectThread = new Thread() {
            @Override
            public void run() {
                while (!isCancellationRequested) {
                    try {
                        if (eventListener != null) {
                            eventListener.dispose();
                        }
                        Logger.getLogger(PersistentSafeguardEventListenerBase.class.getName()).log(Level.FINEST,
                                "Attempting to connect and start internal event listener.");
                        eventListener = reconnectEventListener();
                        eventListener.setEventHandlerRegistry(eventHandlerRegistry);
                        eventListener.SetEventListenerStateCallback(eventListenerStateCallback);
                        eventListener.start();
                        eventListener.setDisconnectHandler(new PersistentReconnectAndStartHandler());
                        break;
                    } catch (ObjectDisposedException | SafeguardForJavaException | ArgumentException ex) {
                        Logger.getLogger(PersistentSafeguardEventListenerBase.class.getName()).log(Level.WARNING,
                                "Internal event listener connection error (see debug for more information), sleeping for 5 seconds...");
                        Logger.getLogger(PersistentSafeguardEventListenerBase.class.getName()).log(Level.FINEST,
                                "Internal event listener connection error.");
                        try {
                            Thread.sleep(5000);
                        } catch (InterruptedException ex1) {
                            isCancellationRequested = true;
                        }
                    }
                }
            }
        };
        
        
        try {
            this.reconnectThread.start();
            this.reconnectThread.join();
        } catch (InterruptedException ex1) {
            isCancellationRequested = true;
        }
        
        this.reconnectThread = null;
    }

    @Override
    public void start() throws ObjectDisposedException {
        if (disposed) {
            throw new ObjectDisposedException("PersistentSafeguardEventListener");
        }
        Logger.getLogger(PersistentSafeguardEventListenerBase.class.getName()).log(Level.INFO, "Internal event listener requested to start.");
        persistentReconnectAndStart();
    }

    @Override
    public void stop() throws ObjectDisposedException, SafeguardForJavaException {
        if (disposed) {
            throw new ObjectDisposedException("PersistentSafeguardEventListener");
        }
        Logger.getLogger(PersistentSafeguardEventListenerBase.class.getName()).log(Level.INFO, "Internal event listener requested to stop.");
        this.isCancellationRequested = true;
        if (eventListener != null) {
            eventListener.stop();
        }
    }

    @Override
    public boolean isStarted() {
        return this.eventListener == null ? false : this.eventListener.isStarted();
    }
    
    @Override
    public void dispose() {
        if (this.eventListener != null) {
            this.eventListener.dispose();
        }
        disposed = true;
    }

    @Override
    protected void finalize() throws Throwable {
        try {
            if (this.eventListener != null) {
                this.eventListener.dispose();
            }
        } finally {
            disposed = true;
        }
    }

}

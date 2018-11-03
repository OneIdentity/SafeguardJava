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

//    private Task _reconnectTask;
//    private CancellationTokenSource _reconnectCancel;
    
    protected PersistentSafeguardEventListenerBase() {
    }

    @Override
    public void registerEventHandler(String eventName, SafeguardEventHandler handler)
            throws ObjectDisposedException {
        if (disposed) {
            throw new ObjectDisposedException("PersistentSafeguardEventListener");
        }
        this.eventHandlerRegistry.registerEventHandler(eventName, handler);
    }

    protected abstract SafeguardEventListener reconnectEventListener() throws ObjectDisposedException, SafeguardForJavaException, ArgumentException;

    private void persistentReconnectAndStart() {
//        if (this.reconnectTask != null)
//            return;
//        this.reconnectCancel = new CancellationTokenSource();
//        _reconnectTask = Task.Run(() =>
//        {
//            while (!_reconnectCancel.IsCancellationRequested)
//            {
//                try
//                {
//                    _eventListener?.Dispose();
//                    Log.Information("Attempting to connect and start internal event listener.");
//                    _eventListener = ReconnectEventListener();
//                    _eventListener.SetEventHandlerRegistry(_eventHandlerRegistry);
//                    _eventListener.Start();
//                    _eventListener.SetDisconnectHandler(PersistentReconnectAndStart);
//                    break;
//                }
//                catch (Exception ex)
//                {
//                    Log.Warning("Internal event listener connection error (see debug for more information), sleeping for 5 seconds...");
//                    Log.Debug(ex, "Internal event listener connection error.");
//                    Thread.Sleep(5000);
//                }
//            }
//        }, _reconnectCancel.Token);
//        _reconnectTask.ContinueWith((task) =>
//        {
//            _reconnectCancel.Dispose();
//            _reconnectCancel = null;
//            _reconnectTask = null;
//            if (!task.IsFaulted)
//                Log.Information("Internal event listener successfully connected and started.");
//        });
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
//        if (reconnectCancel != null)
//            reconnectCancel.cancel();
        if (eventListener != null) {
            eventListener.stop();
        }
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

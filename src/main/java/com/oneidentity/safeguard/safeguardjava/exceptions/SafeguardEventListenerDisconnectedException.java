package com.oneidentity.safeguard.safeguardjava.exceptions;

public class SafeguardEventListenerDisconnectedException extends SafeguardForJavaException {

    public SafeguardEventListenerDisconnectedException() {
        super("SafeguardEventListener has permanently disconnected SignalR connection");
    }

//    protected SafeguardEventListenerDisconnectedException(SerializationInfo info, StreamingContext context) {
//        super(info, context);
//    }
}

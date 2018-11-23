package com.oneidentity.safeguard.safeguardjava.exceptions;

public class SafeguardEventListenerDisconnectedException extends SafeguardForJavaException {

    public SafeguardEventListenerDisconnectedException() {
        super("SafeguardEventListener has permanently disconnected SignalR connection");
    }
}

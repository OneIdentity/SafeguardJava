package com.oneidentity.safeguard.safeguardjava.event;

import com.oneidentity.safeguard.safeguardjava.exceptions.SafeguardEventListenerDisconnectedException;

public interface DisconnectHandler {
    void func() throws SafeguardEventListenerDisconnectedException;
}


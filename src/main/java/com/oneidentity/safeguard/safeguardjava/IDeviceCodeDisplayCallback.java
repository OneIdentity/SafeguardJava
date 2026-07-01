package com.oneidentity.safeguard.safeguardjava;

import com.oneidentity.safeguard.safeguardjava.data.DeviceCodeInfo;

/**
 * Callback used by the Device Code (OAuth 2.0 Device Authorization Grant,
 * RFC 8628) login flow to hand the verification URL and user code to the
 * calling application for display.
 * <p>
 * The SafeguardJava SDK never opens a browser, prints, or logs these values on
 * the caller's behalf. The application is responsible for presenting the
 * verification URL and user code to the end user through whatever channel is
 * appropriate (console, GUI, log, etc.).
 * <p>
 * The callback is <b>required</b> and is invoked exactly once after a successful
 * device authorization response and before polling begins. It never receives
 * the raw {@code device_code}.
 */
public interface IDeviceCodeDisplayCallback {

    /**
     * Called once with the device authorization values to display to the user.
     *
     * @param info The verification URL, user code, and related display values.
     */
    void display(DeviceCodeInfo info);
}

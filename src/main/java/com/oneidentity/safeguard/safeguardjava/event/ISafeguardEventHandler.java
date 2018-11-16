package com.oneidentity.safeguard.safeguardjava.event;

/// <summary>
/// A callback that will be called when a given event occurs in Safeguard. The callback will
/// receive the event name and JSON data representing the event.
/// </summary>
/// <param name="eventName">Name of the event.</param>
/// <param name="eventBody">JSON string containing event data.</param>
//public delegate void ISafeguardEventHandler(string eventName, string eventBody);
public interface ISafeguardEventHandler {
    void func(String eventName, String eventBody);
}


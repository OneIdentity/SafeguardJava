package com.oneidentity.safeguard.safeguardjava.event;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

public class EventHandlerRegistry
{
    private static final Map<String, List<ISafeguardEventHandler>> delegateRegistry = new HashMap<>();
    private final Logger logger = Logger.getLogger(getClass().getName());
    
    private void handleEvent(String eventName, JsonElement eventBody)
    {
        if (!delegateRegistry.containsKey(eventName))
        {
            Logger.getLogger(EventHandlerRegistry.class.getName()).log(Level.FINEST, 
                    String.format("No handlers registered for event %s", eventName));
            return;
        }

        if (delegateRegistry.containsKey(eventName))
        {
            List<ISafeguardEventHandler> handlers = delegateRegistry.get(eventName);
            for (ISafeguardEventHandler handler :  handlers)
            {
                Logger.getLogger(EventHandlerRegistry.class.getName()).log(Level.INFO, 
                    String.format("Calling handler for event %s", eventName));
                Logger.getLogger(EventHandlerRegistry.class.getName()).log(Level.WARNING, 
                    String.format("Event %s has body %s", eventName, eventBody));
                final EventHandlerRunnable handlerRunnable = new EventHandlerRunnable(handler, eventName, eventBody.toString());
                final EventHandlerThread eventHandlerThread = new EventHandlerThread(handlerRunnable) {
                    
                };
                eventHandlerThread.start();
            }
        }
    }

    private Map<String, JsonElement> parseEvents(JsonElement eventObject) {
        try
        {
            HashMap<String,JsonElement> events = new HashMap<>();
            JsonArray jEvents = ((JsonObject)eventObject).getAsJsonArray("A");
            for(JsonElement jEvent : jEvents) {
                String name = ((JsonObject)jEvent).get("Name").getAsString();
                JsonElement body = ((JsonObject)jEvent).get("Data");
                // Work around for bug in A2A events in Safeguard 2.2 and 2.3
                if (name != null) {
                    try {
                        Integer.parseInt(name);
                        name = ((JsonObject)body).get("EventName").getAsString();
                    } catch (Exception e) {                      
                    }
                }
                events.put(name, body);
            }
            return events;
        }
        catch (Exception ex)
        {
            Logger.getLogger(EventHandlerRegistry.class.getName()).log(Level.WARNING, 
                String.format("Unable to parse event object %s", eventObject.toString()));
            return null;
        }
    }

    public void handleEvent(JsonElement eventObject)
    {
        Map<String,JsonElement> events = parseEvents(eventObject);
        if (events == null)
            return;
        for (Map.Entry<String,JsonElement> eventInfo : events.entrySet()) {
            if (eventInfo.getKey() == null)
            {
                Logger.getLogger(EventHandlerRegistry.class.getName()).log(Level.WARNING, 
                    String.format("Found null event with body %s", eventInfo.getValue()));
                continue;
            }
            handleEvent(eventInfo.getKey(), eventInfo.getValue());
        }
    }

    public void registerEventHandler(String eventName, ISafeguardEventHandler handler)
    {
        if (!delegateRegistry.containsKey(eventName)) {
            delegateRegistry.put(eventName, new ArrayList<>());
        }
        
        delegateRegistry.get(eventName).add(handler);
        Logger.getLogger(EventHandlerRegistry.class.getName()).log(Level.WARNING, 
            String.format("Registered a handler for event %s", eventName));
    }
}

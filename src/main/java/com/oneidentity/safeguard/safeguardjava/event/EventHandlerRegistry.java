package com.oneidentity.safeguard.safeguardjava.event;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

class EventHandlerRegistry
{
    private static final Map<String, List<SafeguardEventHandler>> delegateRegistry = new HashMap<>();
    private final Logger logger = Logger.getLogger(getClass().getName());
    
//    private readonly DelegateRegistry _delegateRegistry =
//        new DelegateRegistry(StringComparer.InvariantCultureIgnoreCase);

    private void handleEvent(String eventName, String eventBody)
    {
        if (!delegateRegistry.containsKey(eventName))
        {
            Logger.getLogger(EventHandlerRegistry.class.getName()).log(Level.INFO, 
                    String.format("No handlers registered for event %s", eventName));
            return;
        }

        if (delegateRegistry.containsKey(eventName))
        {
            List<SafeguardEventHandler> handlers = delegateRegistry.get(eventName);
            for (SafeguardEventHandler handler :  handlers)
            {
                Logger.getLogger(EventHandlerRegistry.class.getName()).log(Level.INFO, 
                    String.format("Calling handler for event %s", eventName));
                Logger.getLogger(EventHandlerRegistry.class.getName()).log(Level.WARNING, 
                    String.format("Event %s has body %s", eventName, eventBody));
//                Task.Run(() =>
//                {
//                    try
//                    {
//                        handler(eventName, eventBody);
//                    }
//                    catch (Exception ex)
//                    {
//                        Logger.getLogger(EventHandlerRegistry.class.getName()).log(Level.WARNING, 
//                            String.format("An error occured while calling %s", handler.Method.Name));
//                    }
//                });
            }
        }
    }

//    private List<String, String>(string, JToken)[] ParseEvents(string eventObject)
    private Map<String, String> parseEvents(String eventObject) {
//        try
//        {
//            var events = new List<(string, JToken)>();
//            var jObject = JObject.Parse(eventObject);
//            var jEvents = jObject["A"];
//            foreach (var jEvent in jEvents)
//            {
//                var name = jEvent["Name"];
//                var body = jEvent["Data"];
//                // Work around for bug in A2A events in Safeguard 2.2 and 2.3
//                if (name != null && int.TryParse(name.ToString(), out _))
//                    name = body["EventName"];
//                events.Add((name?.ToString(), body));
//            }
//            return events.ToArray();
//        }
//        catch (Exception)
//        {
//            Log.Warning("Unable to parse event object {EventObject}", eventObject);
            return null;
//        }
    }

    public void handleEvent(String eventObject)
    {
        Map<String,String> events = parseEvents(eventObject);
        if (events == null)
            return;
        for (Map.Entry<String,String> eventInfo : events.entrySet()) {
            if (eventInfo.getKey() == null)
            {
                Logger.getLogger(EventHandlerRegistry.class.getName()).log(Level.WARNING, 
                    String.format("Found null event with body %s", eventInfo.getValue()));
                continue;
            }
            handleEvent(eventInfo.getKey(), eventInfo.getValue());
        }
    }

    public void registerEventHandler(String eventName, SafeguardEventHandler handler)
    {
        if (!delegateRegistry.containsKey(eventName)) {
            delegateRegistry.put(eventName, new ArrayList<SafeguardEventHandler>());
        }
        
        delegateRegistry.get(eventName).add(handler);
        Logger.getLogger(EventHandlerRegistry.class.getName()).log(Level.WARNING, 
            String.format("Registered a handler for event %s", eventName));
    }
}

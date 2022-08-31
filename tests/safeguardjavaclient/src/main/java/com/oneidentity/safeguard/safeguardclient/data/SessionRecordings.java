package com.oneidentity.safeguard.safeguardclient.data;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.ArrayList;
import java.util.List;

class SessionRecording {

    @JsonProperty("key")
    public String sessionId;
}

public class SessionRecordings {
    
    @JsonProperty("items")
    public SessionRecording[] items;
    
    public String[] toArray() {
        List<String> sessionIds = new ArrayList<>();
        for(SessionRecording sr : items) {
            sessionIds.add(sr.sessionId);
        }
        return sessionIds.toArray(new String[sessionIds.size()]);
    }
    
}
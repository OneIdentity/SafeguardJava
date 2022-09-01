package com.oneidentity.safeguard.safeguardjava.data;

public class JsonBody implements JsonObject {
    
    private final String body;
    
    public JsonBody(String body) {
        this.body = body;
    }
    
    @Override
    public String toJson() {
        return body;
    }
}

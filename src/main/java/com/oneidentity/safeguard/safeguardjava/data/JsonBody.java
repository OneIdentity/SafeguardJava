package com.oneidentity.safeguard.safeguardjava.data;

public class JsonBody implements JsonObject {
    
    private String body;
    
    public JsonBody(String body) {
        this.body = body;
    }
    
    public String toJson() {
        return body;
    }
}

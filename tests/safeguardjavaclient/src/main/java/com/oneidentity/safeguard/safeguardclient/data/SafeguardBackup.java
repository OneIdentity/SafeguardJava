package com.oneidentity.safeguard.safeguardclient.data;

public class SafeguardBackup {

    private String Id;
    private String Filename;

    public SafeguardBackup() {
    }

    public String getId() {
        return Id;
    }

    public void setId(String Id) {
        this.Id = Id;
    }

    public String getFilename() {
        return Filename;
    }

    public void setFilename(String Filename) {
        this.Filename = Filename;
    }
}

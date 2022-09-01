package com.oneidentity.safeguard.safeguardclient.data;

import com.fasterxml.jackson.annotation.JsonProperty;

public class SafeguardAppliance {
    @JsonProperty("Id")
    private String Id;
    @JsonProperty("Name")
    private String Name;
    @JsonProperty("Ipv4Address")
    private String Ipv4Address;
    @JsonProperty("Ipv6Address")
    private String Ipv6Address;

    public String getId() {
        return Id;
    }

    public void setId(String Id) {
        this.Id = Id;
    }

    public String getName() {
        return Name;
    }

    public void setName(String Name) {
        this.Name = Name;
    }

    public String getIpv4Address() {
        return Ipv4Address;
    }

    public void setIpv4Address(String Ipv4Address) {
        this.Ipv4Address = Ipv4Address;
    }

    public String getIpv6Address() {
        return Ipv6Address;
    }

    public void setIpv6Address(String Ipv6Address) {
        this.Ipv6Address = Ipv6Address;
    }
    
}

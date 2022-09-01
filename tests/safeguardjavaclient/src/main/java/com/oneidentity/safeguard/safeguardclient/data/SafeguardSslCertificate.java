package com.oneidentity.safeguard.safeguardclient.data;

import com.fasterxml.jackson.annotation.JsonProperty;

public class SafeguardSslCertificate {
    @JsonProperty("Subject")
    private String Subject;
    @JsonProperty("Base64CertificateData")
    private String Base64CertificateData;
    @JsonProperty("IssuerCertificates")
    private String[] IssuerCertificates;
    @JsonProperty("Appliances")
    private SafeguardAppliance[] Appliances;

    public String getSubject() {
        return Subject;
    }

    public void setSubject(String Subject) {
        this.Subject = Subject;
    }

    public String getBase64CertificateData() {
        return Base64CertificateData;
    }

    public void setBase64CertificateData(String Base64CertificateData) {
        this.Base64CertificateData = Base64CertificateData;
    }

    public String[] getIssuerCertificates() {
        return IssuerCertificates;
    }

    public void setIssuerCertificates(String[] IssuerCertificates) {
        this.IssuerCertificates = IssuerCertificates;
    }

    public SafeguardAppliance[] getAppliances() {
        return Appliances;
    }

    public void setAppliances(SafeguardAppliance[] Appliances) {
        this.Appliances = Appliances;
    }
    
}


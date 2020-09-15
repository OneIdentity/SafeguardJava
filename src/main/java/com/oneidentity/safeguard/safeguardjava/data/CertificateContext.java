package com.oneidentity.safeguard.safeguardjava.data;

import com.oneidentity.safeguard.safeguardjava.Utils;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CertificateContext {
    
    private String certificateAlias;
    private String certificatePath;
    private byte[] certificateData;
    private char[] certificatePassword;


    public CertificateContext(String certificateAlias, String certificatePath, byte[] certificateData, char[] certificatePassword) {

        this.certificateAlias = certificateAlias;
        this.certificatePath = certificatePath;
        this.certificateData = certificateData;
        this.certificatePassword = certificatePassword == null ? null : certificatePassword.clone();
    }
    
    private CertificateContext() {
    }

    public String getCertificateAlias() {
        return certificateAlias;
    }

    public void setCertificateAlias(String certificateAlias) {
        this.certificateAlias = certificateAlias;
    }

    public String getCertificatePath() {
        return certificatePath;
    }

    public void setCertificatePath(String certificatePath) {
        this.certificatePath = certificatePath;
    }

    public byte[] getCertificateData() {
        if(certificateData == null) {
            try {
                File file = new File(getCertificatePath());
                certificateData = Files.readAllBytes(file.toPath());
                return certificateData;
            }catch(IOException err){
                Logger.getLogger(CertificateContext.class.getName()).log(Level.WARNING, String.format("Error reading certificate file: %s", err.getMessage()));
            }
        }
        return certificateData;
    }

    public void setCertificateData(byte[] certificateData) {
        this.certificateData = certificateData;
    }
    
    public char[] getCertificatePassword() {
        return certificatePassword;
    }

    public void setCertificatePassword(char[] certificatePassword) {
        this.certificatePassword = certificatePassword;
    }

    public CertificateContext cloneObject()
    {
        CertificateContext clone = new CertificateContext();
        clone.setCertificateAlias(certificateAlias);
        clone.setCertificatePath(certificatePath);
        clone.setCertificateData(certificateData);
        clone.setCertificatePassword(certificatePassword.clone());
        
        return clone;
    }

    @Override
    public String toString()
    {
        if (certificateData != null)
            return "certificateData=[internal-data]";
        
        String result = Utils.isNullOrEmpty(certificatePath) ? String.format("certificateAlias=%s", certificateAlias) : String.format("certificatePath=%s", certificatePath);
        return result;
    }

    public void dispose() {
        if (certificatePassword != null)
            Arrays.fill(certificatePassword, '0');
    }
}

package com.oneidentity.safeguard.safeguardjava.data;

import com.oneidentity.safeguard.safeguardjava.Utils;
import java.util.Arrays;

public class CertificateContext {
    
    private String certificateAlias;
    private String certificatePath;
    private char[] certificatePassword;


    public CertificateContext(String certificateAlias, String certificatePath, char[] certificatePassword) {

        this.certificateAlias = certificateAlias;
        this.certificatePath = certificatePath;
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
        clone.setCertificatePassword(certificatePassword.clone());
        
        return clone;
    }

    @Override
    public String toString()
    {
        String result = Utils.isNullOrEmpty(certificatePath) ? String.format("certificateAlias=%s", certificateAlias) : String.format("certificatePath=%s", certificatePath);
        return result;
    }

    public void dispose() {
        if (certificatePassword != null)
            Arrays.fill(certificatePassword, '0');
    }
}

package com.oneidentity.safeguard.safeguardclient;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSession;

public class CertificateValidator implements HostnameVerifier {

    public static final CertificateValidator INSTANCE = new CertificateValidator();
    
    @Override
    public boolean verify(final String s, final SSLSession sslSession) {
        return true;
    }
    
    @Override
    public final String toString() {
        return "CertificateValidator";
    }
}

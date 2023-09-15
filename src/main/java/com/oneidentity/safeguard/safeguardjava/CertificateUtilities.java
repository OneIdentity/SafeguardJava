package com.oneidentity.safeguard.safeguardjava;

import com.oneidentity.safeguard.safeguardjava.exceptions.SafeguardForJavaException;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
//import javax.xml.bind.DatatypeConverter;
import jakarta.xml.bind.DatatypeConverter;


public class CertificateUtilities {

    private CertificateUtilities() {
    }

    public static String WINDOWSKEYSTORE = "Windows-MY";
    
    public static String getClientCertificateAliasFromStore(String thumbprint) throws SafeguardForJavaException {
        
        try {
            KeyStore keyStore = KeyStore.getInstance(WINDOWSKEYSTORE);
            keyStore.load(null, null);
            
            Enumeration<String> enumeration = keyStore.aliases();
            while (enumeration.hasMoreElements()) {
                String alias = enumeration.nextElement();
                X509Certificate certificate = (X509Certificate)keyStore.getCertificate(alias);
                String t = getThumbprint(certificate);
                if (t != null && thumbprint != null && t.toLowerCase().equals(thumbprint.toLowerCase())) {
                    return alias;
                }
            }
        }
        catch (IOException | KeyStoreException | NoSuchAlgorithmException | CertificateException ex)
        {
            throw new SafeguardForJavaException(String.format("Failure to get certificate from thumbprint=%s : %s", thumbprint, ex.getMessage()));
        }
        
        throw new SafeguardForJavaException(String.format("Unable to find certificate matching thumbprint=%s in the User store", thumbprint));
    }
    
    public static boolean isWindowsKeyStore(String path) {
        return path != null ? path.equalsIgnoreCase(WINDOWSKEYSTORE) : false;
    }
    
    private static String getThumbprint(X509Certificate cert)
            throws NoSuchAlgorithmException, CertificateEncodingException {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        byte[] der = cert.getEncoded();
        md.update(der);
        byte[] digest = md.digest();
        String digestHex = DatatypeConverter.printHexBinary(digest);
        return digestHex.toLowerCase();
    }    
}

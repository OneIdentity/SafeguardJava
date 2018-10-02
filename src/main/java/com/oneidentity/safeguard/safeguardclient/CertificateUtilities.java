package com.oneidentity.safeguard.safeguardclient;

import com.oneidentity.safeguard.safeguardclient.exceptions.SafeguardForJavaException;
import java.security.cert.X509Certificate;

public class CertificateUtilities
{
    private CertificateUtilities() {
    }
    
    public static X509Certificate GetClientCertificateFromStore(String thumbprint) throws SafeguardForJavaException
    {
        try
        {
            X509Certificate cert;
//            using (var store = new X509Store(StoreName.My, StoreLocation.CurrentUser))
//            {
//                store.Open(OpenFlags.ReadOnly);
//                cert = store.Certificates.OfType<X509Certificate>()
//                    .FirstOrDefault(x => x.Thumbprint == thumbprint);
//            }
//            if (cert == null)
//            {
//                using (var store = new X509Store(StoreName.My, StoreLocation.LocalMachine))
//                {
//
//
//                    cert = store.Certificates.OfType<X509Certificate>()
//                        .FirstOrDefault(x => x.Thumbprint == thumbprint);
//                    if (cert == null)
//                        throw new SafeguardForJavaException("Unable to find certificate matching " +
//                                                           String.format("thumbprint=%s in Computer or User store", thumbprint));
//                }
//            }
//            return cert;
return null;
        }
        catch (Exception ex)
        {
            throw new SafeguardForJavaException(String.format("Failure to get certificate from thumbprint=%s", thumbprint), ex);
        }
    }

    public static X509Certificate GetClientCertificateFromFile(String filepath, char[] password) throws SafeguardForJavaException
    {
        try
        {
//            return new X509Certificate(filepath, password);
return null;            
        }
        catch (Exception ex)
        {
            throw new SafeguardForJavaException(String.format("Failure to get certificate from file=%s", filepath), ex);
        }
    }
}

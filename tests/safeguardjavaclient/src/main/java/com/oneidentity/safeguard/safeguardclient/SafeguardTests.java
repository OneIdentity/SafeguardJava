package com.oneidentity.safeguard.safeguardclient;

import static com.oneidentity.safeguard.safeguardclient.SafeguardJavaClient.readLine;
import com.oneidentity.safeguard.safeguardjava.IProgressCallback;
import com.oneidentity.safeguard.safeguardjava.ISafeguardA2AContext;
import com.oneidentity.safeguard.safeguardjava.ISafeguardConnection;
import com.oneidentity.safeguard.safeguardjava.ISafeguardSessionsConnection;
import com.oneidentity.safeguard.safeguardjava.Safeguard;
import com.oneidentity.safeguard.safeguardjava.SafeguardForPrivilegedSessions;
import com.oneidentity.safeguard.safeguardjava.data.A2ARetrievableAccount;
import com.oneidentity.safeguard.safeguardjava.data.BrokeredAccessRequest;
import com.oneidentity.safeguard.safeguardjava.data.BrokeredAccessRequestType;
import com.oneidentity.safeguard.safeguardjava.data.FullResponse;
import com.oneidentity.safeguard.safeguardjava.data.KeyFormat;
import com.oneidentity.safeguard.safeguardjava.data.Method;
import com.oneidentity.safeguard.safeguardjava.data.Service;
import com.oneidentity.safeguard.safeguardjava.event.ISafeguardEventHandler;
import com.oneidentity.safeguard.safeguardjava.event.ISafeguardEventListener;
import com.oneidentity.safeguard.safeguardjava.exceptions.ArgumentException;
import com.oneidentity.safeguard.safeguardjava.exceptions.ObjectDisposedException;
import com.oneidentity.safeguard.safeguardjava.exceptions.SafeguardForJavaException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.stream.Collectors;

public class SafeguardTests {

    public SafeguardTests() {
    }
    
    private void logResponseDetails(FullResponse fullResponse)
    {
        System.out.println(String.format("\t\tReponse status code: %d", fullResponse.getStatusCode()));
        String msg = fullResponse.getHeaders() == null ? "None" : fullResponse.getHeaders().stream().map(header -> header.getName() + "=" + header.getValue()).collect(Collectors.joining(", ", "{", "}"));
        System.out.println(String.format("\t\tResponse headers: %s", msg));
        msg = (fullResponse.getBody() == null) || (fullResponse.getBody().trim().length() == 0) ? "No-Content" : fullResponse.getBody();
        System.out.println(String.format("\t\tBody: %s", msg));
    }

    public ISafeguardConnection safeguardConnectByUserPassword() {
        
        String address = readLine("SPP address: ", null);
        String provider = readLine("Provider:", "local");
        String user = readLine("User:", null);
        String password = readLine("Password: ", null);
        boolean withCertValidator = readLine("With Certificate Validator(y/n): ", "n").equalsIgnoreCase("y");
        boolean ignoreSsl = readLine("Ignore SSL(y/n): ", "y").equalsIgnoreCase("y");
        
        ISafeguardConnection connection = null;
        
        try {
            if (withCertValidator) {
                connection = Safeguard.connect(address, provider, user, password.toCharArray(), new CertificateValidator(), null);
            } else {
                connection = Safeguard.connect(address, provider, user, password.toCharArray(), null, ignoreSsl);
            }
        } catch (ArgumentException | ObjectDisposedException | SafeguardForJavaException ex) {
            System.out.println("\t[ERROR]Connection failed: " + ex.getMessage());
        } catch (Exception ex) {
            System.out.println("\t[ERROR]Connection failed: " + ex.getMessage());
        }
        
        if (connection != null)
            System.out.println("\tSuccessful connection.");
        return connection;
    }
    
    public ISafeguardConnection safeguardConnectByThumbprint() {
        ISafeguardConnection connection = null;

        String address = readLine("SPP address: ", null);
        String thumbprint = readLine("Thumbprint:", null);
        boolean withCertValidator = readLine("With Certificate Validator(y/n): ", "y").equalsIgnoreCase("y");
        boolean ignoreSsl = readLine("Ignore SSL(y/n): ", "y").equalsIgnoreCase("y");
        
        try {
            if (withCertValidator) {
                connection = Safeguard.connect(address, thumbprint, new CertificateValidator(), null);
            } else {
                connection = Safeguard.connect(address, thumbprint, null, ignoreSsl);
            }
        } catch (ObjectDisposedException | SafeguardForJavaException ex) {
            System.out.println("\t[ERROR]Connection failed: " + ex.getMessage());
        } catch (Exception ex) {
            System.out.println("\t[ERROR]Connection failed: " + ex.getMessage());
        }
        
        if (connection != null)
            System.out.println("\tSuccessful connection.");
        return connection;
    }

    public ISafeguardConnection safeguardConnectByCertificate() {
        ISafeguardConnection connection = null;
        
        String address = readLine("SPP address: ", null);
        String provider = readLine("Provider:", null);
        String certificatePath = readLine("Certificate Path:", null);
        String password = readLine("Password: ", null);
        boolean withCertValidator = readLine("With Certificate Validator(y/n): ", "n").equalsIgnoreCase("y");
        boolean ignoreSsl = readLine("Ignore SSL(y/n): ", "y").equalsIgnoreCase("y");
        
        try {
            if (withCertValidator) {
                connection = Safeguard.connect(address, certificatePath, password.toCharArray(), new CertificateValidator(), provider, null);
            } else {
                connection = Safeguard.connect(address, certificatePath, password.toCharArray(), null, ignoreSsl, provider);
            }
        } catch (ObjectDisposedException | SafeguardForJavaException ex) {
            System.out.println("\t[ERROR]Connection failed: " + ex.getMessage());
        } catch (Exception ex) {
            System.out.println("\t[ERROR]Connection failed: " + ex.getMessage());
        }
        
        if (connection != null)
            System.out.println("\tSuccessful connection.");
        return connection;
    }

    public ISafeguardConnection safeguardConnectByToken() {
        ISafeguardConnection connection = null;
        
        String address = readLine("SPP address: ", null);
        String token = readLine("Token:", "local");
        boolean withCertValidator = readLine("With Certificate Validator(y/n): ", "n").equalsIgnoreCase("y");
        boolean ignoreSsl = readLine("Ignore SSL(y/n): ", "y").equalsIgnoreCase("y");
        
        try {
            if (withCertValidator) {
                connection = Safeguard.connect(address, token, new CertificateValidator(), null);
            } else {
                connection = Safeguard.connect(address, token, null, ignoreSsl);
            }
        } catch (ObjectDisposedException | SafeguardForJavaException ex) {
            System.out.println("\t[ERROR]Connection failed: " + ex.getMessage());
        } catch (Exception ex) {
            System.out.println("\t[ERROR]Connection failed: " + ex.getMessage());
        }
        
        if (connection != null)
            System.out.println("\tSuccessful connection.");
        return connection;
    }
    
    public ISafeguardConnection safeguardConnectAnonymous() {
        ISafeguardConnection connection = null;
        
        String address = readLine("SPP address: ", null);
        boolean ignoreSsl = readLine("Ignore SSL(y/n): ", "y").equalsIgnoreCase("y");
        
        try {
            connection = Safeguard.connect(address, null, ignoreSsl);
        } catch (Exception ex) {
            System.out.println("\t[ERROR]Connection failed: " + ex.getMessage());
        }
        
        if (connection != null)
            System.out.println("\tSuccessful connection.");
        return connection;
    }
    
    public ISafeguardConnection safeguardConnectByKeystore() {
        ISafeguardConnection connection = null;
        
        String address = readLine("SPP address: ", null);
        String provider = readLine("Provider:", null);
        String keystorePath = readLine("Keystore Path:", null);
        String password = readLine("Password: ", null);
        String alias = readLine("Alias: ", null);
        boolean withCertValidator = readLine("With Certificate Validator(y/n): ", "n").equalsIgnoreCase("y");
        boolean ignoreSsl = readLine("Ignore SSL(y/n): ", "y").equalsIgnoreCase("y");
        
        try {
            if (withCertValidator) {
                connection = Safeguard.connect(address, keystorePath, password.toCharArray(), alias, new CertificateValidator(), provider, null);
            } else {
                connection = Safeguard.connect(address, keystorePath, password.toCharArray(), alias, provider, null, ignoreSsl);
            }
        } catch (ObjectDisposedException | SafeguardForJavaException ex) {
            System.out.println("\t[ERROR]Connection failed: " + ex.getMessage());
        } catch (Exception ex) {
            System.out.println("\t[ERROR]Connection failed: " + ex.getMessage());
        }
        
        if (connection != null)
            System.out.println("\tSuccessful connection.");
        return connection;
    }
    
    public void safeguardTestConnection(ISafeguardConnection connection) {
        
        if (connection == null) {
            System.out.println(String.format("Safeguard not connected"));
            return;
        }
        
        try {
            int remaining = connection.getAccessTokenLifetimeRemaining();
            System.out.println(String.format("\tTime remaining: %d", remaining));
            
            String response = connection.invokeMethod(Service.Core, Method.Get, "Users", null, null, null, null);
            System.out.println(String.format("\t\\Users response:"));
            System.out.println(response);
            
            FullResponse fullResponse = connection.invokeMethodFull(Service.Core, Method.Get, "Users", null, null, null, null);
            System.out.println(String.format("\t\\Users full response:"));
            logResponseDetails(fullResponse);
            
            fullResponse = connection.invokeMethodFull(Service.Core, Method.Post, "Events/FireTestEvent", null, null, null, null);
            System.out.println(String.format("\t\\FireTestEvent response:"));
            logResponseDetails(fullResponse);
            
            fullResponse = connection.invokeMethodFull(Service.Notification, Method.Get, "Status", null, null, null, null);
            System.out.println(String.format("\t\\Appliance status:"));
            logResponseDetails(fullResponse);
            
            fullResponse = connection.invokeMethodFull(Service.Appliance, Method.Get, "NetworkInterfaces", null, null, null, null);
            System.out.println(String.format("\t\\NetworkInterfaces response:"));
            logResponseDetails(fullResponse);

        } catch (ArgumentException | ObjectDisposedException | SafeguardForJavaException ex) {
            System.out.println("\t[ERROR]Test connection failed: " + ex.getMessage());
        }
    }
    
    public ISafeguardConnection safeguardDisconnect(ISafeguardConnection connection) {
        if (connection != null) {
            connection.dispose();
        }
        return null;
    }

    public ISafeguardA2AContext safeguardGetA2AContextByCertificate() {
        ISafeguardA2AContext a2aContext = null;
        
        String address = readLine("SPP address: ", null);
        String certificatePath = readLine("Certificate Path:", null);
        String password = readLine("Password: ", null);
        boolean withCertValidator = readLine("With Certificate Validator(y/n): ", "n").equalsIgnoreCase("y");
        boolean ignoreSsl = readLine("Ignore SSL(y/n): ", "y").equalsIgnoreCase("y");
        
        try {
            if (withCertValidator) {
                a2aContext = Safeguard.A2A.getContext(address, certificatePath, password.toCharArray(), new CertificateValidator(), null);
            } else {
                a2aContext = Safeguard.A2A.getContext(address, certificatePath, password.toCharArray(), null, ignoreSsl);
            }
        } catch (Exception ex) {
            System.out.println("\t[ERROR]A2AContext failed: " + ex.getMessage());
        }
        
        if (a2aContext != null)
            System.out.println("\tSuccessful A2A context connection.");
        return a2aContext;
    }

    public ISafeguardA2AContext safeguardGetA2AContextByKeystore() {
        ISafeguardA2AContext a2aContext = null;
        
        String address = readLine("SPP address: ", null);
        String keystorePath = readLine("Keystore Path:", null);
        String password = readLine("Password: ", null);
        String alias = readLine("Alias: ", null);
        boolean withCertValidator = readLine("With Certificate Validator(y/n): ", "n").equalsIgnoreCase("y");
        boolean ignoreSsl = readLine("Ignore SSL(y/n): ", "y").equalsIgnoreCase("y");
        
        try {
            if (withCertValidator) {
                a2aContext = Safeguard.A2A.getContext(address, keystorePath, password.toCharArray(), alias, new CertificateValidator(), null);
            } else {
                a2aContext = Safeguard.A2A.getContext(address, keystorePath, password.toCharArray(), alias, null, ignoreSsl);
            }
        } catch (Exception ex) {
            System.out.println("\t[ERROR]A2AContext failed: " + ex.getMessage());
        }
        
        if (a2aContext != null)
            System.out.println("\tSuccessful A2A context connection.");
        return a2aContext;
    }

    ISafeguardA2AContext safeguardGetA2AContextByThumbprint() {
        ISafeguardA2AContext a2aContext = null;
        
        String address = readLine("SPP address: ", null);
        String thumbprint = readLine("Thumbprint:", null);
        boolean withCertValidator = readLine("With Certificate Validator(y/n): ", "y").equalsIgnoreCase("y");
        boolean ignoreSsl = readLine("Ignore SSL(y/n): ", "y").equalsIgnoreCase("y");
        
        try {
            if (withCertValidator) {
                a2aContext = Safeguard.A2A.getContext(address, thumbprint, new CertificateValidator(), null);
            } else {
                a2aContext = Safeguard.A2A.getContext(address, thumbprint, null, ignoreSsl);
            }
        } catch (Exception ex) {
            System.out.println("\t[ERROR]A2AContext failed: " + ex.getMessage());
        }
        
        if (a2aContext != null)
            System.out.println("\tSuccessful A2A context connection.");
        return a2aContext;
    }
    
    public void safeguardTestA2AContext(ISafeguardA2AContext a2aContext) {
        
        if (a2aContext == null) {
            System.out.println(String.format("Missing Safeguard A2A context"));
            return;
        }
        
        if (readLine("Test Credential Retrieval(y/n): ", "y").equalsIgnoreCase("y")) {
            boolean passwordRelease = readLine("Password or Private Key(p/k): ", "p").equalsIgnoreCase("p");
            String apiKey = readLine("API Key: ", null);

            try {
                if (passwordRelease) {
                    String password = new String(a2aContext.retrievePassword(apiKey.toCharArray()));
                    System.out.println(String.format("\tSuccessful password release"));
                }
                else {
                    String key = new String(a2aContext.retrievePrivateKey(apiKey.toCharArray(), KeyFormat.OpenSsh));
                    System.out.println(String.format("\tSuccessful private key release"));
                }

                List<A2ARetrievableAccount> registrations = a2aContext.getRetrievableAccounts();
                System.out.println(String.format("\tRetrievable accounts:"));
                for (A2ARetrievableAccount reg : registrations) {
                    System.out.println(String.format("\t\t%d %s %s", reg.getAccountId(), reg.getAccountName(), reg.getAccountDescription()));
                }
            } catch (ArgumentException | ObjectDisposedException | SafeguardForJavaException ex) {
                System.out.println("\t[ERROR]Test connection failed: " + ex.getMessage());
            }
        }
            
        if (readLine("Test Access Request Broker(y/n): ", "y").equalsIgnoreCase("y")) {
            String accountId = readLine("Account Id: ", null);
            String assetId = readLine("Asset Id:", null);
            String forUserId = readLine("For User Id:", null);
            String accessRequestType = readLine("Access Request Type((p)assword/(s)sh/(r)dp): ", "p");
            String apiKey = readLine("Api Key: ", null);
            
            try {
                BrokeredAccessRequest accessRequest = new BrokeredAccessRequest();
                accessRequest.setAccountId(Integer.parseInt(accountId));
                accessRequest.setForUserId(Integer.parseInt(forUserId));
                accessRequest.setAssetId(Integer.parseInt(assetId));
                accessRequest.setAccessType(accessRequestType.toLowerCase().equals("p") ? BrokeredAccessRequestType.Password 
                        : accessRequestType.toLowerCase().equals("s") ? BrokeredAccessRequestType.Ssh 
                            : BrokeredAccessRequestType.Rdp);
                String result = a2aContext.brokerAccessRequest(apiKey.toCharArray(), accessRequest);

                System.out.println(result);
            } catch (ArgumentException | ObjectDisposedException | SafeguardForJavaException | NumberFormatException ex) {
                System.out.println("\t[ERROR]Test connection failed: " + ex.getMessage());
            }
        }
    }

    public ISafeguardA2AContext safeguardDisconnectA2AContext(ISafeguardA2AContext a2aContext) {
        if (a2aContext != null) {
            a2aContext.dispose();
        }
        return null;
    }
    
    public ISafeguardEventListener safeguardEventListenerByUserPassword() {
        
        String address = readLine("SPP address: ", null);
        String provider = readLine("Provider:", "local");
        String user = readLine("User:", null);
        String password = readLine("Password: ", null);
        boolean withCertValidator = readLine("With Certificate Validator(y/n): ", "n").equalsIgnoreCase("y");
        boolean ignoreSsl = readLine("Ignore SSL(y/n): ", "y").equalsIgnoreCase("y");
        
        ISafeguardEventListener eventListener = null;
        
        try {
            if (withCertValidator) {
                eventListener = Safeguard.Event.getPersistentEventListener(address, provider, user, password.toCharArray(), new CertificateValidator(), null);
            } else {
                eventListener = Safeguard.Event.getPersistentEventListener(address, provider, user, password.toCharArray(), null, ignoreSsl);
            }
        } catch (ArgumentException | ObjectDisposedException | SafeguardForJavaException ex) {
            System.out.println("\t[ERROR]Event listener failed: " + ex.getMessage());
        } catch (Exception ex) {
            System.out.println("\t[ERROR]Event listener failed: " + ex.getMessage());
        }
        
        if (eventListener != null)
            System.out.println("\tSuccessfully create an event listener.");
        return eventListener;
    }
    
    public ISafeguardEventListener safeguardEventListenerByCertificate() {
        
        String address = readLine("SPP address: ", null);
        String provider = readLine("Provider:", null);
        String certificatePath = readLine("Certificate Path:", null);
        String password = readLine("Password: ", null);
        boolean withCertValidator = readLine("With Certificate Validator(y/n): ", "n").equalsIgnoreCase("y");
        boolean ignoreSsl = readLine("Ignore SSL(y/n): ", "y").equalsIgnoreCase("y");

        ISafeguardEventListener eventListener = null;
        
        try {
            if (withCertValidator) {
                eventListener = Safeguard.Event.getPersistentEventListener(address, certificatePath, password.toCharArray(), new CertificateValidator(), provider, null);
            } else {
                eventListener = Safeguard.Event.getPersistentEventListener(address, certificatePath, password.toCharArray(), provider, null, ignoreSsl);
            }
        } catch (ObjectDisposedException | SafeguardForJavaException ex) {
            System.out.println("\t[ERROR]Event listener failed: " + ex.getMessage());
        } catch (Exception ex) {
            System.out.println("\t[ERROR]Event listener failed: " + ex.getMessage());
        }
        
        if (eventListener != null)
            System.out.println("\tSuccessfully create an event listener.");
        return eventListener;
    }

    public ISafeguardEventListener safeguardEventListenerByKeystore() {
        
        String address = readLine("SPP address: ", null);
        String provider = readLine("Provider:", "local");
        String keystorePath = readLine("Keystore Path:", null);
        String password = readLine("Password: ", null);
        String alias = readLine("Alias: ", null);
        boolean withCertValidator = readLine("With Certificate Validator(y/n): ", "n").equalsIgnoreCase("y");
        boolean ignoreSsl = readLine("Ignore SSL(y/n): ", "y").equalsIgnoreCase("y");
        
        ISafeguardEventListener eventListener = null;
        
        try {
            if (withCertValidator) {
                eventListener = Safeguard.Event.getPersistentEventListener(address, keystorePath, password.toCharArray(), alias, new CertificateValidator(), provider, null);
            } else {
                eventListener = Safeguard.Event.getPersistentEventListener(address, keystorePath, password.toCharArray(), alias, provider, null, ignoreSsl);
            }
        } catch (ObjectDisposedException | SafeguardForJavaException ex) {
            System.out.println("\t[ERROR]Event listener failed: " + ex.getMessage());
        } catch (Exception ex) {
            System.out.println("\t[ERROR]Event listener failed: " + ex.getMessage());
        }
        
        if (eventListener != null)
            System.out.println("\tSuccessfully create an event listener.");
        return eventListener;
    }
    
    ISafeguardEventListener safeguardEventListenerByThumbprint() {
        ISafeguardA2AContext a2aContext = null;
        
        String address = readLine("SPP address: ", null);
        String thumbprint = readLine("Thumbprint:", null);
        boolean withCertValidator = readLine("With Certificate Validator(y/n): ", "n").equalsIgnoreCase("y");
        boolean ignoreSsl = readLine("Ignore SSL(y/n): ", "y").equalsIgnoreCase("y");
        
        ISafeguardEventListener eventListener = null;
        
        try {
            if (withCertValidator) {
                eventListener = Safeguard.Event.getPersistentEventListener(address, thumbprint, new CertificateValidator(), null);
            } else {
                eventListener = Safeguard.Event.getPersistentEventListener(address, thumbprint, null, ignoreSsl);
            }
        } catch (ObjectDisposedException | SafeguardForJavaException ex) {
            System.out.println("\t[ERROR]Event listener failed: " + ex.getMessage());
        } catch (Exception ex) {
            System.out.println("\t[ERROR]Event listener failed: " + ex.getMessage());
        }
        
        if (eventListener != null)
            System.out.println("\tSuccessfully create an event listener.");
        return eventListener;
    }

    public void safeguardTestEventListener(ISafeguardEventListener eventListener) {
        
        if (eventListener == null) {
            System.out.println(String.format("\t[ERROR]Missing event listener"));
            return;
        }
        
        String e = readLine("Comma delimited events: ", "UserCreated,UserDeleted");
        
        try {
            String[] events = e.split(",");
            if (events.length == 0) {
                System.out.println(String.format("\t[ERROR]No events specified"));
                return;
            }
            for (String event : events) {
                eventListener.registerEventHandler(event, new ISafeguardEventHandler() {
                    @Override
                    public void onEventReceived(String eventName, String eventBody) {
                        System.out.println(String.format("\tEvent body for %s event", eventName));
                        System.out.println(String.format("\t\t%s", eventBody));
                    }
                });
            }
            
            System.out.print("\tStarting the event listener");
            eventListener.start();
            readLine("Press enter to stop...", null);
            eventListener.stop();
        } catch (ObjectDisposedException | SafeguardForJavaException ex) {
            System.out.println("\t[ERROR]Test event listener failed: " + ex.getMessage());
        } catch (Exception ex) {
            System.out.println("\t[ERROR]Test event listener failed: " + ex.getMessage());
        }
    }
    
    public ISafeguardEventListener safeguardDisconnectEventListener(ISafeguardEventListener eventListener) {
        if (eventListener != null) {
            eventListener.dispose();
        }
        return null;
    }

    public void safeguardTestBackupDownload(ISafeguardConnection connection) {
        
        if (connection == null) {
            System.out.println(String.format("Safeguard not connected"));
            return;
        }

        String backupId = readLine("Backup Id: ", null);
        String backupFileName = readLine("Backup File Name: ", null);
        boolean withProgress = readLine("With Progress Notification(y/n): ", "n").equalsIgnoreCase("y");
        
        if (backupId == null || backupFileName == null) {
            System.out.println(String.format("Missing id or file name"));
            return;
        }
        
        try {
            String filePath = Paths.get(".", backupFileName).toAbsolutePath().toString();
            IProgressCallback progressCallback = withProgress ? new ProgressNotification() : null;
            System.out.println(String.format("\tFile path: %s", filePath));
            connection.getStreamingRequest().downloadStream(Service.Appliance, String.format("Backups/%s/Download", backupId), filePath, progressCallback, null, null);
            System.out.println(String.format("\tDownloaded file: %s", backupFileName));
        } catch (ObjectDisposedException | SafeguardForJavaException ex) {
            System.out.println("\t[ERROR]Test backup download failed: " + ex.getMessage());
        } catch (Exception ex) {
            System.out.println("\t[ERROR]Test backup download failed: " + ex.getMessage());
        }
    }

    public void safeguardTestBackupUpload(ISafeguardConnection connection) {
        
        if (connection == null) {
            System.out.println(String.format("Safeguard not connected"));
            return;
        }

        String backupFileName = readLine("Backup File Name: ", null);
        boolean withProgress = readLine("With Progress Notification(y/n): ", "n").equalsIgnoreCase("y");
        
        if (backupFileName == null) {
            System.out.println(String.format("Missing id or file name"));
            return;
        }
        
        try {
            Path filePath = Paths.get(".", backupFileName).toAbsolutePath();
            IProgressCallback progressCallback = withProgress ? new ProgressNotification() : null;
            byte[] fileContent = Files.readAllBytes(filePath);
            System.out.println(String.format("\tFile path: %s", filePath.toAbsolutePath()));
            connection.getStreamingRequest().uploadStream(Service.Appliance, "Backups/Upload", fileContent, progressCallback, null, null);
            System.out.println(String.format("\tUploaded file: %s", backupFileName));
        } catch (ObjectDisposedException | SafeguardForJavaException ex) {
            System.out.println("\t[ERROR]Test backup download failed: " + ex.getMessage());
        } catch (Exception ex) {
            System.out.println("\t[ERROR]Test backup download failed: " + ex.getMessage());
        }
    }

    ISafeguardSessionsConnection safeguardSessionsConnection() {
        String address = readLine("SPP address: ", null);
        String user = readLine("User:", null);
        String password = readLine("Password: ", null);
//        boolean withCertValidator = readLine("With Certificate Validator(y/n): ", "n").equalsIgnoreCase("y");
        boolean ignoreSsl = readLine("Ignore SSL(y/n): ", "y").equalsIgnoreCase("y");
        
        ISafeguardSessionsConnection connection = null;
        
        try {
//            if (withCertValidator) {
//                connection = Safeguard.connect(address, provider, user, password.toCharArray(), new CertificateValidator(), null);
//            } else {
                connection = SafeguardForPrivilegedSessions.Connect(address, user, password.toCharArray(), true);
//            }
        } catch (SafeguardForJavaException ex) {
            System.out.println("\t[ERROR]Connection failed: " + ex.getMessage());
        } catch (Exception ex) {
            System.out.println("\t[ERROR]Connection failed: " + ex.getMessage());
        }
        
        if (connection != null)
            System.out.println("\tSuccessful connection.");
        return connection;
    }

    void safeguardSessionsApi(ISafeguardSessionsConnection connection) {
        if (connection == null) {
            System.out.println(String.format("Safeguard sessions not connected"));
            return;
        }
        
        try {
            FullResponse fullResponse = connection.InvokeMethodFull(Method.Get, "firmware", null);
            System.out.println(String.format("\t\\Users full response:"));
            logResponseDetails(fullResponse);
            
        } catch (ArgumentException | ObjectDisposedException | SafeguardForJavaException ex) {
            System.out.println("\t[ERROR]Test connection failed: " + ex.getMessage());
        }
    }

    void safeguardTestManagementConnection(ISafeguardConnection connection) {
        if (connection == null) {
            System.out.println(String.format("Safeguard not connected. This test requires an annonymous connection."));
            return;
        }
        
        String address = readLine("SPP address(management service): ", null);
        
        try {
            ISafeguardConnection managementConnection = connection.GetManagementServiceConnection(address);
            FullResponse response = managementConnection.invokeMethodFull(Service.Management, Method.Get, "ApplianceInformation", null, null, null, null);
            System.out.println(String.format("\t\\ApplianceInformation response:"));
            logResponseDetails(response);
        } catch (ArgumentException | ObjectDisposedException | SafeguardForJavaException ex) {
            System.out.println("\t[ERROR]Test management connection failed: " + ex.getMessage());
        }
        
    }
    
    public void safeguardTestAnonymousConnection(ISafeguardConnection connection) {
        
        if (connection == null) {
            System.out.println(String.format("Safeguard not connected"));
            return;
        }
        
        try {
            int remaining = connection.getAccessTokenLifetimeRemaining();
            System.out.println(String.format("\tTime remaining: %d", remaining));
            
            FullResponse fullResponse = connection.invokeMethodFull(Service.Notification, Method.Get, "Status", null, null, null, null);
            System.out.println(String.format("\t\\Appliance status:"));
            logResponseDetails(fullResponse);
            
        } catch (ArgumentException | ObjectDisposedException | SafeguardForJavaException ex) {
            System.out.println("\t[ERROR]Test connection failed: " + ex.getMessage());
        }
    }

}

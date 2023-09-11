package com.oneidentity.safeguard.safeguardclient;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.Gson;
import static com.oneidentity.safeguard.safeguardclient.SafeguardJavaClient.readLine;
import com.oneidentity.safeguard.safeguardclient.data.SafeguardAppliance;
import com.oneidentity.safeguard.safeguardclient.data.SafeguardApplianceStatus;
import com.oneidentity.safeguard.safeguardclient.data.SafeguardBackup;
import com.oneidentity.safeguard.safeguardclient.data.SafeguardSslCertificate;
import com.oneidentity.safeguard.safeguardclient.data.SessionRecordings;
import com.oneidentity.safeguard.safeguardjava.IA2ARetrievableAccount;
import com.oneidentity.safeguard.safeguardjava.IApiKeySecret;
import com.oneidentity.safeguard.safeguardjava.IBrokeredAccessRequest;
import com.oneidentity.safeguard.safeguardjava.IProgressCallback;
import com.oneidentity.safeguard.safeguardjava.ISafeguardA2AContext;
import com.oneidentity.safeguard.safeguardjava.ISafeguardConnection;
import com.oneidentity.safeguard.safeguardjava.ISafeguardSessionsConnection;
import com.oneidentity.safeguard.safeguardjava.Safeguard;
import com.oneidentity.safeguard.safeguardjava.SafeguardForPrivilegedSessions;
import com.oneidentity.safeguard.safeguardjava.data.BrokeredAccessRequest;
import com.oneidentity.safeguard.safeguardjava.data.BrokeredAccessRequestType;
import com.oneidentity.safeguard.safeguardjava.data.FullResponse;
import com.oneidentity.safeguard.safeguardjava.data.KeyFormat;
import com.oneidentity.safeguard.safeguardjava.data.Method;
import com.oneidentity.safeguard.safeguardjava.data.SafeguardEventListenerState;
import com.oneidentity.safeguard.safeguardjava.data.Service;
import com.oneidentity.safeguard.safeguardjava.event.ISafeguardEventHandler;
import com.oneidentity.safeguard.safeguardjava.event.ISafeguardEventListener;
import com.oneidentity.safeguard.safeguardjava.exceptions.ArgumentException;
import com.oneidentity.safeguard.safeguardjava.exceptions.ObjectDisposedException;
import com.oneidentity.safeguard.safeguardjava.exceptions.SafeguardForJavaException;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
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
        String token = readLine("Token:", null);
        boolean withCertValidator = readLine("With Certificate Validator(y/n): ", "n").equalsIgnoreCase("y");
        boolean ignoreSsl = readLine("Ignore SSL(y/n): ", "y").equalsIgnoreCase("y");
        
        try {
            if (withCertValidator) {
                connection = Safeguard.connect(address, token.toCharArray(), new CertificateValidator(), null);
            } else {
                connection = Safeguard.connect(address, token.toCharArray(), null, ignoreSsl);
            }
        } catch (ArgumentException ex) {
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
            char[] token = connection.getAccessToken();
            System.out.println(String.format("\tAccess Token: %s", new String(token)));
            
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
        
        return safeguardGetA2AContextByCertificate(address, certificatePath, password, withCertValidator, ignoreSsl);
    }
    
    private ISafeguardA2AContext safeguardGetA2AContextByCertificate(String address, String certificatePath, String password, boolean withCertValidator, boolean ignoreSsl) {
        ISafeguardA2AContext a2aContext = null;
        
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

    public ISafeguardA2AContext safeguardGetA2AContextByThumbprint() {
        
        String address = readLine("SPP address: ", null);
        String thumbprint = readLine("Thumbprint:", null);
        boolean withCertValidator = readLine("With Certificate Validator(y/n): ", "y").equalsIgnoreCase("y");
        boolean ignoreSsl = readLine("Ignore SSL(y/n): ", "y").equalsIgnoreCase("y");

        return safeguardGetA2AContextByThumbprint(address, thumbprint, withCertValidator, ignoreSsl);
    }
    
    private ISafeguardA2AContext safeguardGetA2AContextByThumbprint(String address, String thumbprint, boolean withCertValidator, boolean ignoreSsl) {
        ISafeguardA2AContext a2aContext = null;
        
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
    
    private byte[] readAllBytes(InputStream in) throws IOException {
        ByteArrayOutputStream baos= new ByteArrayOutputStream();
        byte[] buf = new byte[1024];
        for (int read=0; read != -1; read = in.read(buf)) { baos.write(buf, 0, read); }
            return baos.toByteArray();
    }
    
    private String formatPEM(String resource) throws IOException {
        InputStream in = new ByteArrayInputStream(resource.getBytes());
        String pem = new String(readAllBytes(in), StandardCharsets.ISO_8859_1);
        Pattern parse = Pattern.compile("(?m)(?s)^---*BEGIN.*---*$(.*)^---*END.*---*$.*");
        String encoded = parse.matcher(pem).replaceFirst("$1");
        return encoded.replace("\r", "").replace("\n", "");
    }
    
    public void safeguardTestA2AContext(ISafeguardA2AContext a2aContext) {
        
        if (a2aContext == null) {
            System.out.println(String.format("Missing Safeguard A2A context."));
            return;
        }
        
        if (readLine("Test Credential Retrieval(y/n): ", "y").equalsIgnoreCase("y")) {
            String typeOfRelease = readLine("Password, Private Key or API Key Secret (p/k/a): ", "p");
            String apiKey = readLine("API Key: ", null);

            try {
                if (typeOfRelease.equalsIgnoreCase("p")) {
                    String password = new String(a2aContext.retrievePassword(apiKey.toCharArray()));
                    System.out.println(String.format("\tSuccessful password release"));
                }
                else if (typeOfRelease.equalsIgnoreCase("k")) {
                    String key = new String(a2aContext.retrievePrivateKey(apiKey.toCharArray(), KeyFormat.OpenSsh));
                    System.out.println(String.format("\tSuccessful private key release"));
                }
                else if (typeOfRelease.equalsIgnoreCase("a")) {
                    List<IApiKeySecret> apiKeySecrets = a2aContext.retrieveApiKeySecret(apiKey.toCharArray());
                    if (!apiKeySecrets.isEmpty()) {
                        for (IApiKeySecret key : apiKeySecrets) {
                            System.out.println(String.format("\tKey Id: %d  Key Name: %s", key.getId(), key.getName()));
                        }
                        System.out.println(String.format("\tSuccessful api key secret release"));
                    }
                    else {
                        System.out.println(String.format("\tNo api key secrets found"));
                    }
                }
                else {
                    System.out.println(String.format("Invalid credential release type."));
                    return;
                }
            } catch (ArgumentException | ObjectDisposedException | SafeguardForJavaException ex) {
                System.out.println("\t[ERROR]Test connection failed: " + ex.getMessage());
            }
        }

        if (readLine("Test Setting Credential(y/n): ", "y").equalsIgnoreCase("y")) {
            String typeOfRelease = readLine("Password, Private Key (p/k): ", "p");
            String apiKey = readLine("API Key: ", null);

            try {
                if (typeOfRelease.equalsIgnoreCase("p")) {
                    String newPassword = readLine("New Password: ", "");
                    a2aContext.SetPassword(apiKey.toCharArray(), newPassword.toCharArray());
                    
                    String password = new String(a2aContext.retrievePassword(apiKey.toCharArray()));
                    if (password.compareTo(newPassword) == 0)
                        System.out.println(String.format("\tSuccessfully set password"));
                    else 
                        System.out.println(String.format("\tFailed to set password"));
                }
                else if (typeOfRelease.equalsIgnoreCase("k")) {
                    String privateKeyPath = readLine("Private Key File Path: ", "");
                    String privateKeyPassword = readLine("Private Key Password: ", "");
                    Path filePath = Paths.get(privateKeyPath).toAbsolutePath();
                    String privateKey = new String(Files.readAllBytes(filePath));

                    a2aContext.SetPrivateKey(apiKey.toCharArray(), privateKey.toCharArray(), privateKeyPassword.toCharArray(), KeyFormat.OpenSsh);
                    
                    String key = new String(a2aContext.retrievePrivateKey(apiKey.toCharArray(), KeyFormat.OpenSsh));
                    
                    String privkey1 = formatPEM(privateKey);
                    String privkey2 = formatPEM(key);
                    
                    if (privkey1.compareTo(privkey2) == 0)
                        System.out.println(String.format("\tSuccessful private key release"));
                    else 
                        System.out.println(String.format("\tFailed to set private key"));
                }
                else {
                    System.out.println(String.format("Invalid credential release type."));
                    return;
                }
            } catch (ArgumentException | ObjectDisposedException | SafeguardForJavaException | IOException ex) {
                System.out.println("\t[ERROR]Test connection failed: " + ex.getMessage());
            }
        }
        
        if (readLine("Test Access Request Broker(y/n): ", "y").equalsIgnoreCase("y")) {
            try {
                List<IA2ARetrievableAccount> registrations = a2aContext.getRetrievableAccounts();
                System.out.println(String.format("\tRetrievable accounts:"));
                for (IA2ARetrievableAccount reg : registrations) {
                    System.out.println(String.format("\t\tAssetId: %d AssetName: %s AccountId: %d AccountName: %s AccountDescription: %s", 
                            reg.getAssetId(), reg.getAssetName(), reg.getAccountId(), reg.getAccountName(), reg.getAccountDescription()));
                }
            } catch (ObjectDisposedException | SafeguardForJavaException ex) {
                System.out.println("\t[ERROR]Failed to get the retrievable accounts: " + ex.getMessage());
            }
            
            String accountId = readLine("Account Id: ", null);
            String assetId = readLine("Asset Id:", null);
            String forUserId = readLine("For User Id:", null);
            String accessRequestType = readLine("Access Request Type((p)assword/(s)sh/(r)dp): ", "p");
            String apiKey = readLine("Api Key: ", null);
            
            try {
                IBrokeredAccessRequest accessRequest = new BrokeredAccessRequest();
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

    private List<char[]> ReadAllApiKeys(ISafeguardA2AContext context) throws ObjectDisposedException, SafeguardForJavaException
    {
        List<char[]> apiKeys = new ArrayList<char[]>();
        List<IA2ARetrievableAccount> retrievableAccounts = context.getRetrievableAccounts();
        for (IA2ARetrievableAccount account : retrievableAccounts)
        {
            System.out.println(account.toString());
            apiKeys.add(account.getApiKey());
        }

        return apiKeys;
    }
    
    public ISafeguardEventListener safeguardA2AEventListenerByCertificate() {
        
        String address = readLine("SPP address: ", null);
        String certificatePath = readLine("Certificate Path:", null);
        String password = readLine("Password: ", null);
        boolean withCertValidator = readLine("With Certificate Validator(y/n): ", "n").equalsIgnoreCase("y");
        boolean ignoreSsl = readLine("Ignore SSL(y/n): ", "y").equalsIgnoreCase("y");

        ISafeguardA2AContext a2aContext = safeguardGetA2AContextByCertificate(address, certificatePath, password, withCertValidator, ignoreSsl);

        ISafeguardEventListener eventListener = null;
        
        try {
            List<char[]> apiKeys = ReadAllApiKeys(a2aContext);
            ISafeguardEventHandler a2aHandler = 
                    (String eventName, String eventBody) -> {
                        System.out.println(String.format("\tEvent body for %s event", eventName));
                        System.out.println(String.format("\t\t%s", eventBody));
                    };

            if (withCertValidator) {
                eventListener = Safeguard.A2A.Event.getPersistentA2AEventListener(apiKeys, a2aHandler, address, 
                        certificatePath, password.toCharArray(), new CertificateValidator(), null);
            } else {
                eventListener = Safeguard.A2A.Event.getPersistentA2AEventListener(apiKeys, a2aHandler, address, 
                        certificatePath, password.toCharArray(), null, ignoreSsl);
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
    
    public ISafeguardEventListener safeguardA2AEventListenerByThumbprint() {
        
        String address = readLine("SPP address: ", null);
        String thumbprint = readLine("Thumbprint:", null);
        boolean withCertValidator = readLine("With Certificate Validator(y/n): ", "n").equalsIgnoreCase("y");
        boolean ignoreSsl = readLine("Ignore SSL(y/n): ", "y").equalsIgnoreCase("y");


        ISafeguardA2AContext a2aContext = safeguardGetA2AContextByThumbprint(address, thumbprint, withCertValidator, ignoreSsl);

        ISafeguardEventListener eventListener = null;
        
        try {
            List<char[]> apiKeys = ReadAllApiKeys(a2aContext);
            ISafeguardEventHandler a2aHandler = 
                    (String eventName, String eventBody) -> {
                        System.out.println(String.format("\tEvent body for %s event", eventName));
                        System.out.println(String.format("\t\t%s", eventBody));
                    };

            if (withCertValidator) {
                eventListener = Safeguard.A2A.Event.getPersistentA2AEventListener(apiKeys, a2aHandler, address, 
                        thumbprint, new CertificateValidator(), null);
            } else {
                eventListener = Safeguard.A2A.Event.getPersistentA2AEventListener(apiKeys, a2aHandler, address, 
                        thumbprint, null, ignoreSsl);
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
        String certificatePath = readLine("Certificate Path:", null);
        String password = readLine("Password: ", null);
        boolean withCertValidator = readLine("With Certificate Validator(y/n): ", "n").equalsIgnoreCase("y");
        boolean ignoreSsl = readLine("Ignore SSL(y/n): ", "y").equalsIgnoreCase("y");

        ISafeguardEventListener eventListener = null;
        
        try {
            if (withCertValidator) {
                eventListener = Safeguard.Event.getPersistentEventListener(address, certificatePath, password.toCharArray(), new CertificateValidator(), null);
            } else {
                eventListener = Safeguard.Event.getPersistentEventListener(address, certificatePath, password.toCharArray(), null, ignoreSsl);
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
        
        String e = readLine("Comma delimited events: ", "UserCreated,UserDeleted,TestConnectionFailed,TestConnectionStarted,TestConnectionSucceeded");
        
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

    public void safeguardTestA2AEventListener(ISafeguardEventListener eventListener) {
        
        if (eventListener == null) {
            System.out.println(String.format("\t[ERROR]Missing event listener"));
            return;
        }
        
        try {

            eventListener.SetEventListenerStateCallback((SafeguardEventListenerState eventListenerState) -> {
                System.out.println(String.format("\tGot a SignalR connection state change: %s", eventListenerState.toString()));
            });
            
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

    public void safeguardListBackups(ISafeguardConnection connection) {
        
        if (connection == null) {
            System.out.println(String.format("Safeguard not connected"));
            return;
        }

        try {
            String response = connection.invokeMethod(Service.Appliance, Method.Get, "Backups", null, null, null, null);
            
            SafeguardBackup[] backups = new Gson().fromJson(response, SafeguardBackup[].class);

            System.out.println(String.format("\t\\Backups response:"));
            for (SafeguardBackup backup : backups) {
                System.out.println(String.format("Id: %s - File Name: %s", backup.getId(), backup.getFilename()));
            }
        } catch (ArgumentException | ObjectDisposedException | SafeguardForJavaException ex) {
            System.out.println("\t[ERROR]Test connection failed: " + ex.getMessage());
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
        String address = readLine("SPS address: ", null);
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
            FullResponse fullResponse = connection.invokeMethodFull(Method.Get, "configuration/network/naming", null);
            System.out.println(String.format("\t\\Network Naming full response:"));
            logResponseDetails(fullResponse);
            
        } catch (ArgumentException | ObjectDisposedException | SafeguardForJavaException ex) {
            System.out.println("\t[ERROR]Test connection failed: " + ex.getMessage());
        }
    }

    public void safeguardSessionsFileUpload(ISafeguardSessionsConnection connection) {
        
        if (connection == null) {
            System.out.println("Safeguard not connected");
            return;
        }

        String patchFileName = readLine("SPS Firmware File Name: ", null);
        
        if (patchFileName == null) {
            System.out.println("Missing file name");
            return;
        }
        
        try {
            Path filePath = Paths.get(patchFileName).toAbsolutePath();
            System.out.println(String.format("\tFile path: %s", filePath.toAbsolutePath()));
            
            connection.getStreamingRequest().uploadStream("upload/firmware", filePath.toString(), null, null);
            System.out.println(String.format("\tUploaded file: %s", patchFileName));
        } catch (ObjectDisposedException | SafeguardForJavaException ex) {
            System.out.println("\t[ERROR]Test SPS firmware upload failed: " + ex.getMessage());
        } catch (Exception ex) {
            System.out.println("\t[ERROR]Test SPS firmware upload failed: " + ex.getMessage());
        }
    }

    public void safeguardSessionsStreamUpload(ISafeguardSessionsConnection connection) {
        
        if (connection == null) {
            System.out.println(String.format("Safeguard Sessions not connected"));
            return;
        }

        String patchFileName = readLine("SPS Firmware File Name: ", null);
        boolean withProgress = readLine("With Progress Notification(y/n): ", "n").equalsIgnoreCase("y");
        
        if (patchFileName == null) {
            System.out.println(String.format("file name"));
            return;
        }
        
        try {
            Path filePath = Paths.get(patchFileName).toAbsolutePath();
            IProgressCallback progressCallback = withProgress ? new ProgressNotification() : null;
            byte[] fileContent = Files.readAllBytes(filePath);
            System.out.println(String.format("\tFile path: %s", filePath.toAbsolutePath()));
            
            connection.getStreamingRequest().uploadStream("upload/firmware", fileContent, progressCallback, null, null);
            System.out.println(String.format("\tUploaded file: %s", patchFileName));
        } catch (ObjectDisposedException | SafeguardForJavaException ex) {
            System.out.println("\t[ERROR]Test SPS firmware upload failed: " + ex.getMessage());
        } catch (Exception ex) {
            System.out.println("\t[ERROR]Test SPS firmware upload failed: " + ex.getMessage());
        }
    }

    private String[] safeguardSessionsGetRecordings(ISafeguardSessionsConnection connection) {
        try {
            FullResponse fullResponse = connection.invokeMethodFull(Method.Get, "audit/sessions", null);
            System.out.println(String.format("\t\\Session Id's full response:"));
            logResponseDetails(fullResponse);
            
            ObjectMapper mapper = new ObjectMapper().configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
            SessionRecordings sessionIds = mapper.readValue(fullResponse.getBody(), SessionRecordings.class);
            return sessionIds.toArray();
            
        } catch (ArgumentException | ObjectDisposedException | SafeguardForJavaException ex) {
            System.out.println("\t[ERROR]Get session recordings failed: " + ex.getMessage());
        } catch (JsonProcessingException ex) {
            System.out.println("JSON deserialization failed: " + ex.getMessage());
        }
        
        return null;
    }

    public void safeguardSessionTestRecordingDownload(ISafeguardSessionsConnection connection) {
        
        if (connection == null) {
            System.out.println(String.format("Safeguard not connected"));
            return;
        }

        String[] sessions = safeguardSessionsGetRecordings(connection);
        
        if (sessions == null) {
            System.out.println(String.format("Failed to get the session id's"));
            return;
        }
        
        for (int x = 0; x < sessions.length; x++) {
            System.out.println(String.format("\t%d. %s", x, sessions[x]));
        }

        String s = readLine("Select session: ", "0");
        int sessionSelection = Integer.parseInt(s);
        if (sessionSelection < 0 || sessionSelection > sessions.length-1) {
            System.out.println(String.format("Invalid session selection"));
            return;
        }
                
        String sessionId = sessions[sessionSelection];
        String recordingFileName = sessionId + ".zat";
        boolean withProgress = readLine("With Progress Notification(y/n): ", "n").equalsIgnoreCase("y");

        String filePath = Paths.get(".", recordingFileName).toAbsolutePath().toString();
        IProgressCallback progressCallback = withProgress ? new ProgressNotification() : null;
        
        try {
            System.out.println(String.format("\tSession recording file path: %s", filePath));
            connection.getStreamingRequest().downloadStream(String.format("audit/sessions/%s/audit_trail", sessionId), filePath, progressCallback, null, null);
            System.out.println(String.format("\tDownloaded session recording file: %s", recordingFileName));
        } catch (ObjectDisposedException | SafeguardForJavaException ex) {
            System.out.println("\t[ERROR]Test backup download failed: " + ex.getMessage());
        } catch (Exception ex) {
            System.out.println("\t[ERROR]Test backup download failed: " + ex.getMessage());
        }
    }
    
    public void safeguardTestJoinSps(ISafeguardConnection sppConnection, ISafeguardSessionsConnection spsConnection) {
        if (sppConnection == null) {
            System.out.println(String.format("Safeguard SPP not connected"));
            return;
        }
        if (spsConnection == null) {
            System.out.println(String.format("Safeguard SPS not connected"));
            return;
        }
        
        SafeguardSslCertificate[] sslCerts = null;
        SafeguardApplianceStatus applianceStatus = null;
        try {
            FullResponse fullResponse = sppConnection.invokeMethodFull(Service.Core, Method.Get, "SslCertificates", null, null, null, null);
            System.out.println(String.format("\t\\SslCertificates full response:"));
            logResponseDetails(fullResponse);
            
            ObjectMapper mapper = new ObjectMapper().configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
            sslCerts = mapper.readValue(fullResponse.getBody(), SafeguardSslCertificate[].class);

            fullResponse = sppConnection.invokeMethodFull(Service.Appliance, Method.Get, "ApplianceStatus", null, null, null, null);
            System.out.println(String.format("\t\\ApplianceStatus full response:"));
            logResponseDetails(fullResponse);
            
            applianceStatus = mapper.readValue(fullResponse.getBody(), SafeguardApplianceStatus.class);

        } catch (ArgumentException | ObjectDisposedException | SafeguardForJavaException ex) {
            System.out.println("\t[ERROR]Test Join Sps failed: " + ex.getMessage());
        } catch (JsonProcessingException ex) {
            System.out.println("JSON deserialization failed: " + ex.getMessage());
        }

        if (sslCerts == null || applianceStatus == null) {
            System.out.println("Test Join Sps failed: failed to get the Safeguard appliance information");
            return;
        }
        
        String certChain = null;
        String sppAddress = null;
        for (SafeguardSslCertificate cert : sslCerts) {
            for (SafeguardAppliance sa : cert.getAppliances()) {
                if (sa.getId().equalsIgnoreCase(applianceStatus.getIdentity())) {
                    for (String c : cert.getIssuerCertificates()) {
                        certChain += " "+c.replaceAll("\\r", "");
                    }
                    certChain = certChain == null ? cert.getBase64CertificateData().replaceAll("\\r", "") : cert.getBase64CertificateData().replaceAll("\\r", "")+certChain;
                    sppAddress = sa.getIpv4Address();
                }
            }
        }
        
        try {
            sppConnection.JoinSps(spsConnection, certChain, sppAddress);
        } catch (ObjectDisposedException | SafeguardForJavaException | ArgumentException ex) {
            System.out.println("\t[ERROR]Test Join Sps failed: " + ex.getMessage());
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

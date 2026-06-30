package com.oneidentity.safeguard.safeguardclient;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.oneidentity.safeguard.safeguardjava.ISafeguardA2AContext;
import com.oneidentity.safeguard.safeguardjava.IA2ARetrievableAccount;
import com.oneidentity.safeguard.safeguardjava.IDeviceCodeDisplayCallback;
import com.oneidentity.safeguard.safeguardjava.ISafeguardConnection;
import com.oneidentity.safeguard.safeguardjava.ISafeguardSessionsConnection;
import com.oneidentity.safeguard.safeguardjava.Safeguard;
import com.oneidentity.safeguard.safeguardjava.SafeguardForPrivilegedSessions;
import com.oneidentity.safeguard.safeguardjava.authentication.DeviceCodeLoginParameters;
import com.oneidentity.safeguard.safeguardjava.data.DeviceCodeInfo;
import com.oneidentity.safeguard.safeguardjava.data.FullResponse;
import com.oneidentity.safeguard.safeguardjava.data.Method;
import com.oneidentity.safeguard.safeguardjava.data.Service;
import com.oneidentity.safeguard.safeguardjava.event.ISafeguardEventListener;
import org.apache.hc.core5.http.Header;
import picocli.CommandLine;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Scanner;
import java.util.concurrent.atomic.AtomicReference;

public class SafeguardJavaClient {

    private static final ObjectMapper mapper = new ObjectMapper();

    public static void main(String[] args) {

        if (args.length == 0) {
            runInteractive();
            return;
        }

        ToolOptions opts = new ToolOptions();
        CommandLine cmd = new CommandLine(opts);

        try {
            cmd.parseArgs(args);
        } catch (CommandLine.ParameterException ex) {
            System.err.println("Error: " + ex.getMessage());
            cmd.usage(System.err);
            System.exit(1);
            return;
        }

        if (cmd.isUsageHelpRequested()) {
            cmd.usage(System.out);
            return;
        }

        if (opts.interactive) {
            runInteractive();
            return;
        }

        try {
            if (opts.sps) {
                handleSpsRequest(opts);
                System.exit(0);
                return;
            }

            if (opts.retrievableAccounts || opts.retrievePassword || opts.setPassword) {
                handleA2aOperation(opts);
                System.exit(0);
                return;
            }

            if (opts.deviceCode) {
                handleDeviceCode(opts);
                System.exit(0);
                return;
            }

            ISafeguardConnection connection = createConnection(opts);

            if (opts.resourceOwner != null) {
                setResourceOwnerGrant(connection, opts.resourceOwner);
                System.exit(0);
                return;
            }

            if (opts.tokenLifetime) {
                int remaining = connection.getAccessTokenLifetimeRemaining();
                ObjectNode json = mapper.createObjectNode();
                json.put("TokenLifetimeRemaining", remaining);
                System.out.println(mapper.writeValueAsString(json));
                System.exit(0);
                return;
            }

            if (opts.getToken) {
                char[] token = connection.getAccessToken();
                ObjectNode json = mapper.createObjectNode();
                json.put("AccessToken", new String(token));
                System.out.println(mapper.writeValueAsString(json));
                System.exit(0);
                return;
            }

            if (opts.refreshToken) {
                connection.refreshAccessToken();
                int remaining = connection.getAccessTokenLifetimeRemaining();
                ObjectNode json = mapper.createObjectNode();
                json.put("TokenLifetimeRemaining", remaining);
                System.out.println(mapper.writeValueAsString(json));
                System.exit(0);
                return;
            }

            if (opts.logout) {
                char[] token = connection.getAccessToken();
                ObjectNode json = mapper.createObjectNode();
                json.put("AccessToken", new String(token));
                connection.logOut();
                json.put("LoggedOut", true);
                System.out.println(mapper.writeValueAsString(json));
                System.exit(0);
                return;
            }

            Service service = parseService(opts.service);
            Method method = parseMethod(opts.method);
            Map<String, String> headers = parseKeyValuePairs(opts.headers);
            Map<String, String> parameters = parseKeyValuePairs(opts.parameters);

            if (opts.file != null) {
                String result = handleStreamingRequest(opts, connection, service, method, headers, parameters);
                System.out.println(result);
            } else if (opts.full) {
                FullResponse response = connection.invokeMethodFull(service, method,
                        opts.relativeUrl, opts.body, parameters, headers, null);
                ObjectNode json = mapper.createObjectNode();
                json.put("StatusCode", response.getStatusCode());
                ArrayNode headersArray = json.putArray("Headers");
                for (Header h : response.getHeaders()) {
                    ObjectNode headerObj = mapper.createObjectNode();
                    headerObj.put("Name", h.getName());
                    headerObj.put("Value", h.getValue());
                    headersArray.add(headerObj);
                }
                json.put("Body", response.getBody());
                System.out.println(mapper.writeValueAsString(json));
            } else {
                String result = connection.invokeMethod(service, method,
                        opts.relativeUrl, opts.body, parameters, headers, null);
                System.out.println(result);
            }

            System.exit(0);
        } catch (Exception ex) {
            System.err.println("Error: " + ex.getMessage());
            if (opts.verbose) {
                ex.printStackTrace(System.err);
            }
            System.exit(1);
        }
    }

    private static String handleStreamingRequest(ToolOptions opts, ISafeguardConnection connection,
            Service service, Method method, Map<String, String> headers,
            Map<String, String> parameters) throws Exception {
        if (method == Method.Post) {
            byte[] fileContent = Files.readAllBytes(new File(opts.file).toPath());
            return connection.getStreamingRequest().uploadStream(service, opts.relativeUrl,
                    fileContent, null, parameters, headers);
        } else if (method == Method.Get) {
            File outFile = new File(opts.file);
            if (outFile.exists()) {
                throw new IllegalStateException("File exists, remove it first: " + opts.file);
            }
            connection.getStreamingRequest().downloadStream(service, opts.relativeUrl,
                    opts.file, null, parameters, headers);
            return "Download written to " + opts.file;
        } else {
            throw new IllegalArgumentException("Streaming is not supported for HTTP method: " + opts.method);
        }
    }

    private static void handleA2aOperation(ToolOptions opts) throws Exception {
        Scanner stdinScanner = new Scanner(System.in);

        char[] certPassword = null;
        if (opts.readPassword) {
            System.err.print("Password: ");
            certPassword = stdinScanner.nextLine().toCharArray();
        }

        ISafeguardA2AContext a2aContext;
        if (opts.certificateFile != null) {
            System.err.println("Creating A2A context for " + opts.appliance + " with certificate file " + opts.certificateFile);
            a2aContext = Safeguard.A2A.getContext(opts.appliance, opts.certificateFile, certPassword, null, opts.insecure);
        } else if (opts.thumbprint != null) {
            System.err.println("Creating A2A context for " + opts.appliance + " with thumbprint " + opts.thumbprint);
            a2aContext = Safeguard.A2A.getContext(opts.appliance, opts.thumbprint, null, opts.insecure);
        } else {
            throw new IllegalArgumentException(
                    "A2A operations require a certificate (-c or -t).");
        }

        try {
            if (opts.retrievableAccounts) {
                List<IA2ARetrievableAccount> accounts;
                if (opts.filter != null && opts.filter.length() > 0) {
                    System.err.println("Retrieving accounts with filter: " + opts.filter);
                    accounts = a2aContext.getRetrievableAccounts(opts.filter);
                } else {
                    System.err.println("Retrieving all accounts");
                    accounts = a2aContext.getRetrievableAccounts();
                }
                System.out.println(mapper.writeValueAsString(accounts));
            } else if (opts.retrievePassword) {
                if (opts.apiKey == null || opts.apiKey.length() == 0) {
                    throw new IllegalArgumentException("--retrieve-password requires --api-key");
                }
                System.err.println("Retrieving password via A2A");
                char[] password = a2aContext.retrievePassword(opts.apiKey.toCharArray());
                System.out.println(new String(password));
            } else if (opts.setPassword) {
                if (opts.apiKey == null || opts.apiKey.length() == 0) {
                    throw new IllegalArgumentException("--set-password requires --api-key");
                }
                System.err.print("New password: ");
                char[] newPassword = stdinScanner.nextLine().toCharArray();
                System.err.println("Setting password via A2A");
                a2aContext.SetPassword(opts.apiKey.toCharArray(), newPassword);
                System.out.println("OK");
            }
        } finally {
            a2aContext.dispose();
        }
    }

    private static void handleSpsRequest(ToolOptions opts) throws Exception {
        char[] password = null;
        if (opts.readPassword) {
            System.err.print("Password: ");
            password = new Scanner(System.in).nextLine().toCharArray();
        }

        System.err.println("Connecting to SPS " + opts.appliance + " as " + opts.username);
        ISafeguardSessionsConnection spsConnection = SafeguardForPrivilegedSessions.Connect(
                opts.appliance, opts.username, password, opts.insecure);

        Method method = parseMethod(opts.method);

        if (opts.full) {
            FullResponse response = spsConnection.invokeMethodFull(method, opts.relativeUrl, opts.body);
            ObjectNode json = mapper.createObjectNode();
            json.put("StatusCode", response.getStatusCode());
            ArrayNode headersArray = json.putArray("Headers");
            for (Header h : response.getHeaders()) {
                ObjectNode headerObj = mapper.createObjectNode();
                headerObj.put("Name", h.getName());
                headerObj.put("Value", h.getValue());
                headersArray.add(headerObj);
            }
            json.put("Body", response.getBody());
            System.out.println(mapper.writeValueAsString(json));
        } else {
            String result = spsConnection.invokeMethod(method, opts.relativeUrl, opts.body);
            System.out.println(result);
        }
    }

    private static void handleDeviceCode(ToolOptions opts) throws Exception {
        final AtomicReference<DeviceCodeInfo> captured = new AtomicReference<>();

        DeviceCodeLoginParameters params = new DeviceCodeLoginParameters();
        if (opts.identityProvider != null && !opts.identityProvider.trim().isEmpty()) {
            params.setScope("rsts:sts:primaryproviderid:" + opts.identityProvider);
        }
        // Without a human to approve, cancel as soon as the verification values are received.
        params.setIsCancelled(() -> captured.get() != null);

        IDeviceCodeDisplayCallback displayCallback = info -> {
            captured.set(info);
            System.err.println("To sign in, visit "
                    + (info.getVerificationUriComplete() != null
                            ? info.getVerificationUriComplete() : info.getVerificationUri())
                    + " and enter code " + info.getUserCode());
        };

        System.err.println("Connecting to " + opts.appliance + " via Device Code flow");
        try {
            ISafeguardConnection connection = Safeguard.connectDeviceCode(
                    opts.appliance, displayCallback, params, (Integer) null, opts.insecure);
            // A human approved within the deadline.
            String me = connection.invokeMethod(Service.Core, Method.Get, "Me", null, null, null, null);
            ObjectNode json = mapper.createObjectNode();
            json.put("Approved", true);
            json.set("Me", mapper.readTree(me));
            System.out.println(mapper.writeValueAsString(json));
            connection.dispose();
        } catch (Exception ex) {
            DeviceCodeInfo info = captured.get();
            if (info != null) {
                // Expected no-human path: report the display values that were received.
                ObjectNode json = mapper.createObjectNode();
                ObjectNode display = json.putObject("DeviceCodeDisplay");
                display.put("UserCode", info.getUserCode());
                display.put("VerificationUri", info.getVerificationUri());
                if (info.getVerificationUriComplete() != null) {
                    display.put("VerificationUriComplete", info.getVerificationUriComplete());
                }
                display.put("ExpiresIn", info.getExpiresIn());
                System.out.println(mapper.writeValueAsString(json));
                return;
            }
            // No display values means the request failed (e.g. grant disabled); surface the error.
            throw ex;
        }
    }

    private static ISafeguardConnection createConnection(ToolOptions opts) throws Exception {
        char[] password = null;
        if (opts.readPassword) {
            System.err.print("Password: ");
            password = new Scanner(System.in).nextLine().toCharArray();
        }

        // Resource owner toggle always uses PKCE
        boolean usePkce = opts.pkce || opts.resourceOwner != null;

        if (opts.username != null) {
            String provider = opts.identityProvider != null ? opts.identityProvider : "local";
            if (usePkce) {
                System.err.println("Connecting to " + opts.appliance + " as " + opts.username + " via " + provider + " (PKCE)");
                return Safeguard.connectPkce(opts.appliance, provider, opts.username, password, (Integer) null, opts.insecure);
            } else {
                System.err.println("Connecting to " + opts.appliance + " as " + opts.username + " via " + provider);
                return Safeguard.connect(opts.appliance, provider, opts.username, password, null, opts.insecure);
            }
        }

        if (opts.certificateFile != null) {
            System.err.println("Connecting to " + opts.appliance + " with certificate file " + opts.certificateFile);
            return Safeguard.connect(opts.appliance, opts.certificateFile, password, null, opts.insecure, null);
        }

        if (opts.thumbprint != null) {
            System.err.println("Connecting to " + opts.appliance + " with thumbprint " + opts.thumbprint);
            return Safeguard.connect(opts.appliance, opts.thumbprint, null, opts.insecure);
        }

        if (opts.accessToken != null) {
            System.err.println("Connecting to " + opts.appliance + " with access token");
            return Safeguard.connect(opts.appliance, opts.accessToken.toCharArray(), null, opts.insecure);
        }

        if (opts.anonymous) {
            System.err.println("Connecting to " + opts.appliance + " anonymously");
            return Safeguard.connect(opts.appliance, null, opts.insecure);
        }

        throw new IllegalArgumentException(
                "No authentication method specified. Use -u, -c, -t, -k, or -A.");
    }

    private static Service parseService(String serviceStr) {
        if (serviceStr == null) {
            throw new IllegalArgumentException("Service (-s) is required for API invocation");
        }
        switch (serviceStr.toLowerCase()) {
            case "core": return Service.Core;
            case "appliance": return Service.Appliance;
            case "notification": return Service.Notification;
            case "a2a": return Service.A2A;
            default:
                throw new IllegalArgumentException("Unknown service: " + serviceStr
                        + ". Valid values: Core, Appliance, Notification, A2A");
        }
    }

    private static Method parseMethod(String methodStr) {
        if (methodStr == null) {
            throw new IllegalArgumentException("Method (-m) is required for API invocation");
        }
        switch (methodStr.toLowerCase()) {
            case "get": return Method.Get;
            case "post": return Method.Post;
            case "put": return Method.Put;
            case "delete": return Method.Delete;
            default:
                throw new IllegalArgumentException("Unknown method: " + methodStr
                        + ". Valid values: Get, Post, Put, Delete");
        }
    }

    private static Map<String, String> parseKeyValuePairs(String[] pairs) {
        Map<String, String> map = new HashMap<>();
        if (pairs == null) {
            return map;
        }
        for (String pair : pairs) {
            int idx = pair.indexOf('=');
            if (idx < 0) {
                throw new IllegalArgumentException("Invalid Key=Value pair: " + pair);
            }
            map.put(pair.substring(0, idx), pair.substring(idx + 1));
        }
        return map;
    }

    private static final String GRANT_TYPE_SETTING_NAME = "Allowed OAuth2 Grant Types";

    private static void setResourceOwnerGrant(ISafeguardConnection connection, boolean enable)
            throws Exception {
        String settingsJson = connection.invokeMethod(Service.Core, Method.Get, "Settings",
                null, null, null, null);
        JsonNode settings = mapper.readTree(settingsJson);

        JsonNode grantSetting = null;
        if (settings.isArray()) {
            for (JsonNode node : settings) {
                JsonNode nameNode = node.get("Name");
                if (nameNode != null && GRANT_TYPE_SETTING_NAME.equals(nameNode.asText())) {
                    grantSetting = node;
                    break;
                }
            }
        }
        if (grantSetting == null) {
            throw new RuntimeException("Setting '" + GRANT_TYPE_SETTING_NAME + "' not found");
        }

        String currentValue = grantSetting.has("Value") && !grantSetting.get("Value").isNull()
                ? grantSetting.get("Value").asText() : "";

        String[] parts = currentValue.split(",");
        java.util.List<String> grantTypes = new java.util.ArrayList<>();
        for (String part : parts) {
            String trimmed = part.trim();
            if (!trimmed.isEmpty()) {
                grantTypes.add(trimmed);
            }
        }

        boolean hasResourceOwner = false;
        for (String gt : grantTypes) {
            if (gt.equalsIgnoreCase("ResourceOwner")) {
                hasResourceOwner = true;
                break;
            }
        }

        if (enable && !hasResourceOwner) {
            grantTypes.add("ResourceOwner");
        } else if (!enable && hasResourceOwner) {
            java.util.Iterator<String> it = grantTypes.iterator();
            while (it.hasNext()) {
                if (it.next().equalsIgnoreCase("ResourceOwner")) {
                    it.remove();
                }
            }
        }

        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < grantTypes.size(); i++) {
            if (i > 0) sb.append(", ");
            sb.append(grantTypes.get(i));
        }
        String newValue = sb.toString();

        ObjectNode body = mapper.createObjectNode();
        body.put("Value", newValue);
        connection.invokeMethod(Service.Core, Method.Put,
                "Settings/" + java.net.URLEncoder.encode(GRANT_TYPE_SETTING_NAME, "UTF-8")
                        .replace("+", "%20"),
                mapper.writeValueAsString(body), null, null, null);

        ObjectNode envelope = mapper.createObjectNode();
        envelope.put("Setting", GRANT_TYPE_SETTING_NAME);
        envelope.put("PreviousValue", currentValue);
        envelope.put("NewValue", newValue);
        envelope.put("ResourceOwnerEnabled", enable);
        System.out.println(mapper.writeValueAsString(envelope));
    }

    private static void runInteractive() {

        ISafeguardConnection connection = null;
        ISafeguardSessionsConnection sessionConnection = null;
        ISafeguardA2AContext a2aContext = null;
        ISafeguardEventListener eventListener = null;
        ISafeguardEventListener a2aEventListener = null;

        boolean done = false;
        SafeguardTests tests = new SafeguardTests();

        // Uncomment the lines below to enable console debug logging of the http requests
        //System.setProperty("org.apache.commons.logging.Log","org.apache.commons.logging.impl.SimpleLog");
        //System.setProperty("org.apache.commons.logging.simplelog.showdatetime", "true");
        //System.setProperty("org.apache.commons.logging.simplelog.log.org.apache.http.wire", "DEBUG");

        //System.setProperty("org.apache.commons.logging.simplelog.log.org.apache.http.impl.conn", "DEBUG");
        //System.setProperty("org.apache.commons.logging.simplelog.log.org.apache.http.impl.client", "DEBUG");
        //System.setProperty("org.apache.commons.logging.simplelog.log.org.apache.http.client", "DEBUG");
        //System.setProperty("org.apache.commons.logging.simplelog.log.org.apache.http", "DEBUG");

        try {
            while (!done) {
                Integer selection = displayMenu();

                switch(selection) {
                    case 1:
                        connection = tests.safeguardConnectByUserPassword();
                        break;
                    case 2:
                        connection = tests.safeguardConnectByThumbprint();
                        break;
                    case 3:
                        connection = tests.safeguardConnectByCertificate();
                        break;
                    case 4:
                        connection = tests.safeguardConnectByToken();
                        break;
                    case 5:
                        connection = tests.safeguardConnectAnonymous();
                        break;
                    case 6:
                        connection = tests.safeguardConnectByKeystore();
                        break;
                    case 7:
                        tests.safeguardTestConnection(connection);
                        break;
                    case 8:
                        connection = tests.safeguardDisconnect(connection);
                        break;
                    case 9:
                        a2aContext = tests.safeguardGetA2AContextByCertificate();
                        break;
                    case 10:
                        a2aContext = tests.safeguardGetA2AContextByKeystore();
                        break;
                    case 11:
                        a2aContext = tests.safeguardGetA2AContextByThumbprint();
                        break;
                    case 12:
                        tests.safeguardTestA2AContext(a2aContext);
                        break;
                    case 13:
                        a2aContext = tests.safeguardDisconnectA2AContext(a2aContext);
                        break;
                    case 14:
                        eventListener = tests.safeguardEventListenerByUserPassword();
                        break;
                    case 15:
                        eventListener = tests.safeguardEventListenerByCertificate();
                        break;
                    case 16:
                        eventListener = tests.safeguardEventListenerByKeystore();
                        break;
                    case 17:
                        eventListener = tests.safeguardEventListenerByThumbprint();
                        break;
                    case 18:
                        tests.safeguardTestEventListener(eventListener);
                        break;
                    case 19:
                        a2aEventListener = tests.safeguardA2AEventListenerByCertificate();
                        break;
                    case 20:
                        a2aEventListener = tests.safeguardA2AEventListenerByThumbprint();
                        break;
                    case 21:
                        tests.safeguardTestA2AEventListener(a2aEventListener);
                        break;
                    case 22:
                        {
                            if (eventListener != null) {
                                eventListener = tests.safeguardDisconnectEventListener(eventListener);
                            }
                            if (a2aEventListener != null) {
                                a2aEventListener = tests.safeguardDisconnectEventListener(a2aEventListener);
                            }
                        }
                        break;
                    case 23:
                        tests.safeguardListBackups(connection);
                        break;
                    case 24:
                        tests.safeguardTestBackupDownload(connection);
                        break;
                    case 25:
                        tests.safeguardTestBackupUpload(connection);
                        break;
                    case 26:
                        sessionConnection = tests.safeguardSessionsConnection();
                        break;
                    case 27:
                        tests.safeguardSessionsApi(sessionConnection);
                        break;
                    case 28:
                        tests.safeguardSessionsFileUpload(sessionConnection);
                        break;
                    case 29:
                        tests.safeguardSessionsStreamUpload(sessionConnection);
                        break;
                    case 30:
                        tests.safeguardSessionTestRecordingDownload(sessionConnection);
                        break;
                    case 31:
                        tests.safeguardTestJoinSps(connection, sessionConnection);
                        break;
                    case 32:
                        tests.safeguardTestManagementConnection(connection);
                        break;
                    case 33:
                        tests.safeguardTestAnonymousConnection(connection);
                        break;
                    default:
                        done = true;
                        break;
                }
            }
        } catch (Exception ex) {
            System.out.println("Exception Type: " + ex.getClass().getCanonicalName());
            System.out.println("/tMessage: " + ex.getMessage());
            System.out.println("/tException Stack: ");
            ex.printStackTrace();
        }

        System.out.println("All done.");
    }

    private static Integer displayMenu() {

        System.out.println("Select an option:");
        System.out.println ("\t1. Connect by user/password");
        System.out.println ("\t2. Connect by thumbprint");
        System.out.println ("\t3. Connect by certificate file");
        System.out.println ("\t4. Connect by token");
        System.out.println ("\t5. Connect anonymous");
        System.out.println ("\t6. Connect by keystore");
        System.out.println ("\t7. Test Connection");
        System.out.println ("\t8. Disconnect");
        System.out.println ("\t9. A2AContext by certificate file");
        System.out.println ("\t10. A2AContext by keystore");
        System.out.println ("\t11. A2AContext by thumbprint");
        System.out.println ("\t12. Test A2AContext");
        System.out.println ("\t13. Disconnect A2AContext");
        System.out.println ("\t14. Event Listener by user/password");
        System.out.println ("\t15. Event Listener by certificate file");
        System.out.println ("\t16. Event Listener by keystore");
        System.out.println ("\t17. Event Listener by thumbprint");
        System.out.println ("\t18. Test Event Listener");
        System.out.println ("\t19. A2A Event Listener by certificate file");
        System.out.println ("\t20. A2A Event Listener by thumbprint");
        System.out.println ("\t21. Test A2A Event Listener");
        System.out.println ("\t22. Disconnect Event Listener");
        System.out.println ("\t23. Test List Backups");
        System.out.println ("\t24. Test Download Backup File");
        System.out.println ("\t25. Test Upload Backup File");
        System.out.println ("\t26. Test SPS Connection");
        System.out.println ("\t27. Test SPS API");
        System.out.println ("\t28. Test SPS Firmware Upload");
        System.out.println ("\t29. Test Stream Upload");
        System.out.println ("\t30. Test Session Recording Download");
        System.out.println ("\t31. Test Join SPS");
        System.out.println ("\t32. Test Management Interface API");
        System.out.println ("\t33. Test Anonymous Connection");

        System.out.println ("\t99. Exit");

        System.out.print ("Selection: ");
        Scanner in = new Scanner(System.in);
        int selection = in.nextInt();

        return selection;
    }

    public static String toJsonString(String name, Object value, boolean prependSep) {
        if (value != null) {
            return (prependSep ? ", " : "") + "\"" + name + "\" : " + (value instanceof String ? "\"" + value.toString() + "\"" : value.toString());
        }
        return "";
    }

    public static String readLine(String format, String defaultStr, Object... args) {

        String value = defaultStr;
        format += "["+defaultStr+"] ";
        try {
            if (System.console() != null) {
                value = System.console().readLine(format, args);
            } else {
                System.out.print(String.format(format, args));
                BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
                value = reader.readLine();
            }
        } catch(IOException ex) {
            System.out.println(ex.getMessage());
            return defaultStr;
        }

        if (value.trim().length() == 0)
            return defaultStr;
        return value.trim();
    }
}

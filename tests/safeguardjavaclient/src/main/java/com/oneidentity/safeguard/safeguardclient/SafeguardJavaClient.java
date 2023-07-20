package com.oneidentity.safeguard.safeguardclient;

import com.oneidentity.safeguard.safeguardjava.ISafeguardA2AContext;
import com.oneidentity.safeguard.safeguardjava.ISafeguardConnection;
import com.oneidentity.safeguard.safeguardjava.ISafeguardSessionsConnection;
import com.oneidentity.safeguard.safeguardjava.event.ISafeguardEventListener;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Scanner;

public class SafeguardJavaClient {

    public static void main(String[] args) {

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
    
    private static CommandLine parseArguments(String[] args) {

        Options options = getOptions();
        CommandLine line = null;

        CommandLineParser parser = new DefaultParser();

        try {
            line = parser.parse(options, args);

        } catch (ParseException ex) {

            System.err.println(ex);
            printAppHelp();

            System.exit(1);
        }

        return line;
    }

    private static Options getOptions() {

        Options options = new Options();

        options.addOption("f", "filename", true,
                "file name to load data from");
        return options;
    }

    private static void printAppHelp() {

        Options options = getOptions();

        HelpFormatter formatter = new HelpFormatter();
        formatter.printHelp("SafeguardClientCli", options, true);
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

//class EventHandler implements ISafeguardEventHandler {
//
//    @Override
//    public void onEventReceived(String eventName, String eventBody) {
//        System.out.println("Got the event");
//    }
//}

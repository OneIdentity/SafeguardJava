package com.oneidentity.safeguard.samples;

import com.oneidentity.safeguard.safeguardjava.ISafeguardConnection;
import com.oneidentity.safeguard.safeguardjava.Safeguard;
import com.oneidentity.safeguard.safeguardjava.data.Method;
import com.oneidentity.safeguard.safeguardjava.data.Service;

/**
 * Demonstrates connecting to Safeguard using the OAuth 2.0 Device Authorization
 * Grant (Device Code flow, RFC 8628).
 * <p>
 * This flow is intended for headless or no-browser environments. The SDK never
 * opens a browser; this sample prints the verification URL and user code, and
 * the user completes authentication in a browser on any device. The SDK polls
 * until the login succeeds, is denied, expires, or is cancelled.
 * <p>
 * The Device Code grant must be enabled on the appliance under
 * Settings -&gt; OAuth 2.0 Grant Types.
 */
public class DeviceCodeConnect {

    public static void main(String[] args) {
        if (args.length < 1) {
            System.out.println("Usage: DeviceCodeConnect <appliance>");
            System.out.println();
            System.out.println("  appliance  - IP address or hostname of Safeguard appliance");
            return;
        }

        String appliance = args[0];

        ISafeguardConnection connection = null;
        try {
            // Connect using Device Code. The caller-provided callback is responsible
            // for displaying the verification URL and user code — printing here is
            // sample behavior, not library behavior. Set ignoreSsl=true for lab
            // environments; use a HostnameVerifier in production.
            connection = Safeguard.connectDeviceCode(appliance, info -> {
                String url = info.getVerificationUriComplete() != null
                        ? info.getVerificationUriComplete()
                        : info.getVerificationUri();
                System.out.println();
                System.out.println("To sign in, use a web browser to open:");
                System.out.println("    " + url);
                System.out.println("and enter the code:");
                System.out.println("    " + info.getUserCode());
                System.out.println();
                System.out.println("Waiting for you to complete authentication "
                        + "(expires in " + info.getExpiresIn() + " seconds)...");
            }, null, null, true);

            // Call the "Me" endpoint to get info about the authenticated user
            String me = connection.invokeMethod(Service.Core, Method.Get, "Me",
                    null, null, null, null);
            System.out.println("Current user info:");
            System.out.println(me);

        } catch (Exception ex) {
            System.err.println("Error: " + ex.getMessage());
            ex.printStackTrace();
        } finally {
            if (connection != null) {
                connection.dispose();
            }
        }
    }
}

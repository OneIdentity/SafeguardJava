// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

package com.microsoft.signalr;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.logging.Level;
import java.util.logging.Logger;

class Connect {
    public static String resolveConnectUrl(String url, String connectionToken) {
        String connectUrl = "";

        // Check if we have a query string. If we do then we ignore it for now.
        int queryStringIndex = url.indexOf('?');
        if (queryStringIndex > 0) {
            connectUrl = url.substring(0, url.indexOf('?'));
        } else {
            connectUrl = url;
        }

        //Check if the url ends in a /
        if (connectUrl.charAt(connectUrl.length() - 1) != '/') {
            connectUrl += "/";
        }

        try {
            connectUrl += "signalr/connect?transport=webSockets&connectionToken=" +
                    URLEncoder.encode(connectionToken, "UTF-8") +
                    "&connectionData=" + URLEncoder.encode("[{\"name\":\"notificationHub\"}]", "UTF-8");
        } catch (UnsupportedEncodingException ex) {
            Logger.getLogger(Connect.class.getName()).log(Level.SEVERE, null, ex);
        }
        
//        // Add the query string back if it existed.
//        if (queryStringIndex > 0) {
//            connectUrl += url.substring(url.indexOf('?'));
//        }

        return connectUrl;
    }
}

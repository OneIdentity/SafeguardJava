/*
Copyright (c) Microsoft Open Technologies, Inc.
All Rights Reserved
See License.txt in the project root for license information.
*/

package microsoft.aspnet.signalr.client;

import java.util.Map;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;

import microsoft.aspnet.signalr.client.http.Request;
import microsoft.aspnet.signalr.client.transport.ClientTransport;

public interface ConnectionBase {

    /**
     * Returns the URL used by the connection
     * @return Url
     */
    public String getUrl();

    /**
     * Returns the credentials used by the connection
     * @return Credentials
     */
    public Credentials getCredentials();

    /**
     * Sets the credentials the connection should use
     * @param credentials Credentials
     */
    public void setCredentials(Credentials credentials);

    /**
     * Sets the message id the connection should use
     * @param messageId Message Id
     */
    public void setMessageId(String messageId);

    /**
     * Sets the groups token the connection should use
     * @param groupsToken Group Token
     */
    public void setGroupsToken(String groupsToken);

    /**
     * Sets the handler for the "Reconnecting" event
     * @param handler Handler
     */
    public void reconnecting(Runnable handler);

    /**
     * Sets the handler for the "Reconnected" event
     * @param handler Handler
     */
    public void reconnected(Runnable handler);

    /**
     * Sets the handler for the "Connected" event
     * @param handler Handler
     */
    public void connected(Runnable handler);

    /**
     * Sets the handler for the "Error" event
     * @param handler Error Handler
     */
    public void error(ErrorCallback handler);

    /**
     * Sets the handler for the "StateChanged" event
     * @param handler State change handler
     */
    public void stateChanged(StateChangedCallback handler);

    /**
     * Triggers the Error event
     * 
     * @param error
     *            The error that triggered the event
     * @param mustCleanCurrentConnection
     *            True if the connection must be cleaned
     */
    public void onError(Throwable error, boolean mustCleanCurrentConnection);

    /**
     * Sets the handler for the "Received" event
     * @param handler Message received handler
     */
    public void received(MessageReceivedHandler handler);

    public void onReceived(JsonElement message);

    /**
     * Sets the handler for the "ConnectionSlow" event
     * @param handler Handler
     */
    public void connectionSlow(Runnable handler);

    /**
     * Sets the handler for the "Closed" event
     * @param handler Handler
     */
    public void closed(Runnable handler);

    /**
     * Returns the connection token
     * @return  String Connection token
     */
    public String getConnectionToken();

    /**
     * Returns the connection Id
     * @return String Connection Id
     */
    public String getConnectionId();

    /**
     * Returns the query string used by the connection
     * @return String QueryString
     */
    public String getQueryString();

    /**
     * Returns the current message Id
     * @return String Message Id
     */
    public String getMessageId();

    /**
     * Returns the connection groups token
     * @return String Groups Token
     */
    public String getGroupsToken();

    /**
     * Returns the data used by the connection
     * @return String Connection Data
     */
    public String getConnectionData();

    /**
     * Returns the connection state
     * @return ConnectionState State
     */
    public ConnectionState getState();

    /**
     * Starts the connection
     * 
     * @param transport
     *            Transport to be used by the connection
     * @return Future for the operation
     */
    public SignalRFuture<Void> start(ClientTransport transport);

    /**
     * Aborts the connection and closes it
     */
    public void stop();

    /**
     * Closes the connection
     */
    public void disconnect();

    /**
     * Sends data using the connection
     * 
     * @param data
     *            Data to send
     * @return Future for the operation
     */
    public SignalRFuture<Void> send(String data);

    /**
     * Prepares a request that is going to be sent to the server
     * 
     * @param request
     *            The request to prepare
     */
    void prepareRequest(Request request);

    /**
     * Returns the connection headers
     * @return Map Headers
     */
    Map<String, String> getHeaders();

    /**
     * Returns the Gson instance used by the connection
     * @return Gson instance
     */
    Gson getGson();

    /**
     * Sets the Gson instance used by the connection
     * @param gson Gson instance
     */
    void setGson(Gson gson);

    /**
     * Returns the JsonParser used by the connection
     * @return JsonParser Json parser
     */
    JsonParser getJsonParser();

    /**
     * Returns the Logger used by the connection
     * @return Logger Logger
     */
    public Logger getLogger();
    
    /**
     * Set the client certificate information
     * 
     * @param clientCertificatePath client certificate path
     * @param clientCertificatePassword client certificate password
     * @param clientCertificateAlias client certificate alias
     */
    void setClientCertificate(String clientCertificatePath, char[] clientCertificatePassword, String clientCertificateAlias);
    
}
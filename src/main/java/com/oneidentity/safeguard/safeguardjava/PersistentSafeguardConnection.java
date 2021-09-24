package com.oneidentity.safeguard.safeguardjava;

import com.oneidentity.safeguard.safeguardjava.data.FullResponse;
import com.oneidentity.safeguard.safeguardjava.data.Method;
import com.oneidentity.safeguard.safeguardjava.data.Service;
import com.oneidentity.safeguard.safeguardjava.event.ISafeguardEventListener;
import com.oneidentity.safeguard.safeguardjava.event.SafeguardEventListener;
import com.oneidentity.safeguard.safeguardjava.exceptions.ArgumentException;
import com.oneidentity.safeguard.safeguardjava.exceptions.ObjectDisposedException;
import com.oneidentity.safeguard.safeguardjava.exceptions.SafeguardForJavaException;
import java.util.Map;

class PersistentSafeguardConnection implements ISafeguardConnection {
    
    private final ISafeguardConnection _connection;
    private boolean disposed;

    public PersistentSafeguardConnection(ISafeguardConnection connection) {
        _connection = connection;
    }

    public IStreamingRequest getStreamingRequest() {
        return _connection.getStreamingRequest();
    }

    @Override
    public void dispose()
    {
        _connection.dispose();
    }

    public FullResponse JoinSps(ISafeguardSessionsConnection spsConnection, String certificateChain, String sppAddress) 
            throws ObjectDisposedException, SafeguardForJavaException, ArgumentException
    {
        if (_connection.getAccessTokenLifetimeRemaining() <= 0)
            _connection.refreshAccessToken();
        return _connection.JoinSps(spsConnection, certificateChain, sppAddress);
    }

    @Override
    public int getAccessTokenLifetimeRemaining() throws ObjectDisposedException, SafeguardForJavaException {
        return _connection.getAccessTokenLifetimeRemaining();
    }

    @Override
    public void refreshAccessToken() throws ObjectDisposedException, SafeguardForJavaException {
        _connection.refreshAccessToken();
    }

    @Override
    public String invokeMethod(Service service, Method method, String relativeUrl, String body, Map<String, String> parameters, Map<String, String> additionalHeaders, Integer timeout) throws ObjectDisposedException, SafeguardForJavaException, ArgumentException {
        if(_connection.getAccessTokenLifetimeRemaining() <= 0)
            _connection.refreshAccessToken();
        return _connection.invokeMethod(service, method, relativeUrl, body, parameters, additionalHeaders, timeout);
    }

    @Override
    public FullResponse invokeMethodFull(Service service, Method method, String relativeUrl, String body, Map<String, String> parameters, Map<String, String> additionalHeaders, Integer timeout) throws ObjectDisposedException, SafeguardForJavaException, ArgumentException {
        if (_connection.getAccessTokenLifetimeRemaining() <= 0)
            _connection.refreshAccessToken();
        return _connection.invokeMethodFull(service, method, relativeUrl, body, parameters, additionalHeaders, timeout);
    }

    @Override
    public String invokeMethodCsv(Service service, Method method, String relativeUrl, String body, Map<String, String> parameters, Map<String, String> additionalHeaders, Integer timeout) throws ObjectDisposedException, SafeguardForJavaException, ArgumentException {
        if (_connection.getAccessTokenLifetimeRemaining() <= 0)
            _connection.refreshAccessToken();
        return _connection.invokeMethodCsv(service, method, relativeUrl, body, parameters, additionalHeaders, timeout);
    }

    @Override
    public SafeguardEventListener getEventListener() throws ObjectDisposedException, ArgumentException {
        return _connection.getEventListener();
    }

    @Override
    public ISafeguardEventListener getPersistentEventListener() throws ObjectDisposedException, SafeguardForJavaException {
        return _connection.getPersistentEventListener();
    }

    @Override
    public void logOut() throws ObjectDisposedException {
        _connection.logOut();
    }

}

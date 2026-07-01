package com.oneidentity.safeguard.safeguardjava.authentication;

import com.oneidentity.safeguard.safeguardjava.exceptions.ArgumentException;
import java.util.function.Supplier;

/**
 * Tunable parameters for the Device Code (OAuth 2.0 Device Authorization Grant,
 * RFC 8628) login flow.
 * <p>
 * All parameters are optional and have sensible defaults that match the
 * SafeguardDotNet implementation:
 * <ul>
 *   <li>{@code scope} selects the authentication provider; defaults to the
 *       local provider.</li>
 *   <li>{@code clientId} defaults to empty, which the rSTS normalizes to its
 *       built-in application client id.</li>
 *   <li>{@code pollingIntervalSeconds} defaults to 5 and is automatically
 *       increased by 5 seconds when the appliance returns {@code slow_down}.</li>
 *   <li>{@code isCancelled} is a caller-driven cancel hook (the idiomatic Java
 *       stand-in for .NET's {@code CancellationToken}); by default the flow is
 *       never cancelled.</li>
 * </ul>
 * The poll deadline is always the appliance's {@code expires_in} value and is
 * not configurable here.
 */
public class DeviceCodeLoginParameters {

    /** Default scope, selecting the built-in local authentication provider. */
    public static final String DEFAULT_SCOPE = "rsts:sts:primaryproviderid:local";

    /** Default polling interval in seconds. */
    public static final int DEFAULT_POLLING_INTERVAL_SECONDS = 5;

    private String scope = DEFAULT_SCOPE;
    private String clientId = "";
    private int pollingIntervalSeconds = DEFAULT_POLLING_INTERVAL_SECONDS;
    private Supplier<Boolean> isCancelled = () -> Boolean.FALSE;

    /**
     * Gets the scope used to select the authentication provider.
     *
     * @return The scope value.
     */
    public String getScope() {
        return scope;
    }

    /**
     * Sets the scope used to select the authentication provider. A null or empty
     * value resets the scope to {@link #DEFAULT_SCOPE}.
     *
     * @param scope The scope value.
     */
    public void setScope(String scope) {
        this.scope = (scope == null || scope.trim().isEmpty()) ? DEFAULT_SCOPE : scope;
    }

    /**
     * Gets the OAuth client id. An empty value lets the rSTS use its built-in
     * application client id.
     *
     * @return The client id.
     */
    public String getClientId() {
        return clientId;
    }

    /**
     * Sets the OAuth client id. A null value is treated as empty.
     *
     * @param clientId The client id.
     */
    public void setClientId(String clientId) {
        this.clientId = clientId == null ? "" : clientId;
    }

    /**
     * Gets the polling interval in seconds.
     *
     * @return The polling interval in seconds.
     */
    public int getPollingIntervalSeconds() {
        return pollingIntervalSeconds;
    }

    /**
     * Sets the polling interval in seconds.
     *
     * @param pollingIntervalSeconds The polling interval; must be greater than zero.
     * @throws ArgumentException If the value is less than or equal to zero.
     */
    public void setPollingIntervalSeconds(int pollingIntervalSeconds) throws ArgumentException {
        if (pollingIntervalSeconds <= 0) {
            throw new ArgumentException("The pollingIntervalSeconds parameter must be greater than zero");
        }
        this.pollingIntervalSeconds = pollingIntervalSeconds;
    }

    /**
     * Gets the caller-driven cancel hook.
     *
     * @return A supplier that returns {@code true} when the flow should be cancelled.
     */
    public Supplier<Boolean> getIsCancelled() {
        return isCancelled;
    }

    /**
     * Sets the caller-driven cancel hook. A null value disables cancellation.
     *
     * @param isCancelled A supplier that returns {@code true} when the flow should be cancelled.
     */
    public void setIsCancelled(Supplier<Boolean> isCancelled) {
        this.isCancelled = isCancelled == null ? () -> Boolean.FALSE : isCancelled;
    }
}

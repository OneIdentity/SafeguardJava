package com.oneidentity.safeguard.safeguardjava;

import com.oneidentity.safeguard.safeguardjava.data.BrokeredAccessRequestType;
import java.time.Instant;

/**
 * Represents a brokered access request
 */
public interface IBrokeredAccessRequest {

    /**
     * Get the type of access request to create.
     * @return BrokeredAccessRequestType
     */
    BrokeredAccessRequestType getAccessType();

    /**
     * Set the type of access request to create.
     * @param AccessType BrokeredAccessRequestType
     */
    void setAccessType(BrokeredAccessRequestType AccessType);

    /**
     * Get the name of the user to create the access request for. If the ForUserId property is
     * set, then this property will be ignored.
     * @return String
     */
    String getForUserName();

    /**
     * Set the name of the user to create the access request for. If the ForUserId property is
     * set, then this property will be ignored.
     * @param ForUserName For user name
     */
    void setForUserName(String ForUserName);

    /**
     * Get the name of the identity provider to create the access request for. If the ForUserId
     * property is set, then this property will be ignored.
     * @return String
     */
    String getForUserIdentityProvider();

    /**
     * Set the name of the identity provider to create the access request for. If the ForUserId
     * property is set, then this property will be ignored.
     * @param ForUserIdentityProvider Identity provider
     */
    void setForUserIdentityProvider(String ForUserIdentityProvider);

    /**
     * Get the ID of the user to create the access request for.
     * @return Integer
     */
    Integer getForUserId();

    /**
     * Set the ID of the user to create the access request for.
     * @param ForUserId For user id.
     */
    void setForUserId(Integer ForUserId);

    /**
     * Get the name of the asset to create the access request for. If the AssetId property is
     * set, then this property will be ignored.
     * @return String
     */
    String getAssetName();

    /**
     * Set the name of the asset to create the access request for. If the AssetId property is
     * set, then this property will be ignored.
     * @param AssetName Asset name.
     */
    void setAssetName(String AssetName);

    /**
     * Get the ID of the asset to create the access request for.
     * @return Integer
     */
    Integer getAssetId();

    /**
     * Set the ID of the asset to create the access request for.
     * @param AssetId Asset id.
     */
    void setAssetId(Integer AssetId);

    /**
     * Get the name of the account to create the access request for. If the AccountId property is
     * set, then this property will be ignored.
     * @return String
     */
    String getAccountName();

    /**
     * Set the name of the account to create the access request for. If the AccountId property is
     * set, then this property will be ignored.
     * @param AccountName Account name.
     */
    void setAccountName(String AccountName);

    /**
     * Get the ID of the account to create the access request for.
     * @return Integer
     */
    Integer getAccountId();

    /**
     * Set the ID of the account to create the access request for.
     * @param AccountId Account id.
     */
    void setAccountId(Integer AccountId);

    /**
     * Get the name of the asset the account is from to create the access request for. If the
     * AccountAssetId property is set, then this property will be ignored.
     * @return String
     */
    String getAccountAssetName();

    /**
     * Set the name of the asset the account is from to create the access request for. If the
     * AccountAssetId property is set, then this property will be ignored.
     * @param AccountAssetName Account asset name.
     */
    void setAccountAssetName(String AccountAssetName);

    /**
     * Get the ID of the asset the account is from to create the access request for.
     * @return Integer
     */
    Integer getAccountAssetId();

    /**
     * Set the ID of the asset the account is from to create the access request for.
     * @param AccountAssetId Account asset id.
     */
    void setAccountAssetId(Integer AccountAssetId);

    /**
     * Whether or not this is an emergency access request.
     * @return boolean
     */
    boolean getIsEmergency();

    /**
     * Set whether or not this is an emergency access request.
     * @param IsEmergency Is emergency
     */
    void setIsEmergency(boolean IsEmergency);

    /**
     * Get the name of the pre-defined reason code to include in the access request. If the ReasonCodeId
     * property is set, then this property will be ignored.
     * @return String
     */
    String getReasonCode();

    /**
     * Set the name of the pre-defined reason code to include in the access request. If the ReasonCodeId
     * property is set, then this property will be ignored.
     * @param ReasonCode Reason code.
     */
    void setReasonCode(String ReasonCode);

    /**
     * Get the ID of the pre-defined reason code to include in the access request.
     * @return Integer
     */
    Integer getReasonCodeId();

    /**
     * Set the ID of the pre-defined reason code to include in the access request.
     * @param ReasonCodeId Reason code id.
     */
    void setReasonCodeId(Integer ReasonCodeId);

    /**
     * Get a reason comment to include in the access request.
     * @return String
     */
    String getReasonComment();

    /**
     * Set a reason comment to include in the access request.
     * @param ReasonComment Reason comment.
     */
    void setReasonComment(String ReasonComment);

    /**
     * Get a ticket number associated with the new access request.
     * @return String
     */
    String getTicketNumber();

    /**
     * Set a ticket number associated with the new access request.
     * @param TicketNumber Ticket number.
     */
    void setTicketNumber(String TicketNumber);

    /**
     * Get the time when the access request should be requested for. All values will be converted to UTC date and time
     * before being sent to the server.
     * @return Instant
     */
    Instant getRequestedFor();

    /**
     * Set the time when the access request should be requested for. All values will be converted to UTC date and time
     * before being sent to the server.
     * @param RequestedFor Requested for.
     */
    void setRequestedFor(Instant RequestedFor);

    /**
     * Get the number of days the access request should be requested for.
     * @return Long
     */
    Long getRequestedDurationDays();

    /**
     * Set the number of days the access request should be requested for.
     * @param RequestedDurationDays Requested duration days
     */
    void setRequestedDurationDays(Long RequestedDurationDays);

    /**
     * Get the number of hours the access request should be requested for.
     * @return Long
     */
    Long getRequestedDurationHours();

    /**
     * Set the number of hours the access request should be requested for.
     * @param RequestedDurationHours Requested duration hours
     */
    void setRequestedDurationHours(Long RequestedDurationHours);

    /**
     * Get the number of minutes the access request should be requested for.
     * @return Long
     */
    Long getRequestedDurationMinutes();

    /**
     * Set the number of minutes the access request should be requested for.
     * @param RequestedDurationMinutes Requested duration minutes
     */
    void setRequestedDurationMinutes(Long RequestedDurationMinutes);
}

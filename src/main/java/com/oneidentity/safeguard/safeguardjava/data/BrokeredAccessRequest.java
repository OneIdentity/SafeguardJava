package com.oneidentity.safeguard.safeguardjava.data;

import com.oneidentity.safeguard.safeguardjava.Utils;
import java.time.Instant;
import java.util.Date;

/**
 * This class is used to define a brokered access request.
 */
public class BrokeredAccessRequest implements JsonObject
{

    private BrokeredAccessRequestType AccessType;   // converted by AccessRequestTypeConverter
    private String ForUserName;
    private String ForUserIdentityProvider;         // renamed from ForProvider
    private Integer ForUserId;
    private String AssetName;                       // renamed from SystemName
    private Integer AssetId;                        // renamed from SystemId
    private String AccountName;
    private Integer AccountId;
    private String AccountAssetName;                // renamed from AccountSystemName
    private Integer AccountAssetId;                 // renamed from AccountSystemId
    private boolean IsEmergency;
    private String ReasonCode;
    private Integer ReasonCodeId;
    private String ReasonComment;
    private String TicketNumber;
    private Instant RequestedFor;                   // converted by UtcDateTimeConverter
    private Long RequestedDurationDays;             // converted by CustomTimeSpanConverter
    private Long RequestedDurationHours;
    private Long RequestedDurationMinutes;

    
    /**
     * Get the type of access request to create.
     * @return BrokeredAccessRequestType
     */
    public BrokeredAccessRequestType getAccessType() {
        return AccessType;
    }

    /**
     * Set the type of access request to create.
     * @param AccessType BrokeredAccessRequestType
     */
    public void setAccessType(BrokeredAccessRequestType AccessType) {
        this.AccessType = AccessType;
    }

    /**
     * Get the name of the user to create the access request for. If the ForUserId property is
     * set, then this property will be ignored.
     * @return String
     */
    public String getForUserName() {
        return ForUserName;
    }

    /**
     * Set the name of the user to create the access request for. If the ForUserId property is
     * set, then this property will be ignored.
     * @param ForUserName For user name
     */
    public void setForUserName(String ForUserName) {
        this.ForUserName = ForUserName;
    }

    /**
     * Get the name of the identity provider to create the access request for. If the ForUserId
     * property is set, then this property will be ignored.
     * @return String
     */
    public String getForUserIdentityProvider() {
        return ForUserIdentityProvider;
    }

    /**
     * Set the name of the identity provider to create the access request for. If the ForUserId
     * property is set, then this property will be ignored.
     * @param ForUserIdentityProvider Identity provider
     */
    public void setForUserIdentityProvider(String ForUserIdentityProvider) {
        this.ForUserIdentityProvider = ForUserIdentityProvider;
    }

    /**
     * Get the ID of the user to create the access request for.
     * @return Integer
     */
    public Integer getForUserId() {
        return ForUserId;
    }

    /**
     * Set the ID of the user to create the access request for.
     * @param ForUserId For user id.
     */
    public void setForUserId(Integer ForUserId) {
        this.ForUserId = ForUserId;
    }

    /**
     * Get the name of the asset to create the access request for. If the AssetId property is
     * set, then this property will be ignored.
     * @return String
     */
    public String getAssetName() {
        return AssetName;
    }

    /**
     * Set the name of the asset to create the access request for. If the AssetId property is
     * set, then this property will be ignored.
     * @param AssetName Asset name.
     */
    public void setAssetName(String AssetName) {
        this.AssetName = AssetName;
    }

    /**
     * Get the ID of the asset to create the access request for.
     * @return Integer
     */
    public Integer getAssetId() {
        return AssetId;
    }

    /**
     * Set the ID of the asset to create the access request for.
     * @param AssetId Asset id.
     */
    public void setAssetId(Integer AssetId) {
        this.AssetId = AssetId;
    }

    /**
     * Get the name of the account to create the access request for. If the AccountId property is
     * set, then this property will be ignored.
     * @return String
     */
    public String getAccountName() {
        return AccountName;
    }

    /**
     * Set the name of the account to create the access request for. If the AccountId property is
     * set, then this property will be ignored.
     * @param AccountName Account name.
     */
    public void setAccountName(String AccountName) {
        this.AccountName = AccountName;
    }

    /**
     * Get the ID of the account to create the access request for.
     * @return Integer
     */
    public Integer getAccountId() {
        return AccountId;
    }

    /**
     * Set the ID of the account to create the access request for.
     * @param AccountId Account id.
     */
    public void setAccountId(Integer AccountId) {
        this.AccountId = AccountId;
    }

    /**
     * Get the name of the asset the account is from to create the access request for. If the
     * AccountAssetId property is set, then this property will be ignored.
     * @return String
     */
    public String getAccountAssetName() {
        return AccountAssetName;
    }

    /**
     * Set the name of the asset the account is from to create the access request for. If the
     * AccountAssetId property is set, then this property will be ignored.
     * @param AccountAssetName Account asset name.
     */
    public void setAccountAssetName(String AccountAssetName) {
        this.AccountAssetName = AccountAssetName;
    }

    /**
     * Get the ID of the asset the account is from to create the access request for.
     * @return Integer
     */
    public Integer getAccountAssetId() {
        return AccountAssetId;
    }

    /**
     * Set the ID of the asset the account is from to create the access request for.
     * @param AccountAssetId Account asset id.
     */
    public void setAccountAssetId(Integer AccountAssetId) {
        this.AccountAssetId = AccountAssetId;
    }

    /**
     * Whether or not this is an emergency access request.
     * @return boolean
     */
    public boolean getIsEmergency() {
        return IsEmergency;
    }

    /**
     * Set whether or not this is an emergency access request.
     * @param IsEmergency Is emergency
     */
    public void setIsEmergency(boolean IsEmergency) {
        this.IsEmergency = IsEmergency;
    }

    /**
     * Get the name of the pre-defined reason code to include in the access request. If the ReasonCodeId
     * property is set, then this property will be ignored.
     * @return String
     */
    public String getReasonCode() {
        return ReasonCode;
    }

    /**
     * Set the name of the pre-defined reason code to include in the access request. If the ReasonCodeId
     * property is set, then this property will be ignored.
     * @param ReasonCode Reason code.
     */
    public void setReasonCode(String ReasonCode) {
        this.ReasonCode = ReasonCode;
    }

    /**
     * Get the ID of the pre-defined reason code to include in the access request.
     * @return Integer
     */
    public Integer getReasonCodeId() {
        return ReasonCodeId;
    }

    /**
     * Set the ID of the pre-defined reason code to include in the access request.
     * @param ReasonCodeId Reason code id.
     */
    public void setReasonCodeId(Integer ReasonCodeId) {
        this.ReasonCodeId = ReasonCodeId;
    }

    /**
     * Get a reason comment to include in the access request.
     * @return String
     */
    public String getReasonComment() {
        return ReasonComment;
    }

    /**
     * Set a reason comment to include in the access request.
     * @param ReasonComment Reason comment.
     */
    public void setReasonComment(String ReasonComment) {
        this.ReasonComment = ReasonComment;
    }

    /**
     * Get a ticket number associated with the new access request.
     * @return String
     */
    public String getTicketNumber() {
        return TicketNumber;
    }

    /**
     * Set a ticket number associated with the new access request.
     * @param TicketNumber Ticket number.
     */
    public void setTicketNumber(String TicketNumber) {
        this.TicketNumber = TicketNumber;
    }

    /**
     * Get the time when the access request should be requested for. All values will be converted to UTC date and time
     * before being sent to the server.
     * @return Instant
     */
    public Instant getRequestedFor() {
        return RequestedFor;
    }

    /**
     * Set the time when the access request should be requested for. All values will be converted to UTC date and time
     * before being sent to the server.
     * @param RequestedFor Requested for.
     */
    public void setRequestedFor(Instant RequestedFor) {
        this.RequestedFor = RequestedFor;
    }

    /**
     * Get the number of days the access request should be requested for.
     * @return Long
     */
    public Long getRequestedDurationDays() {
        return RequestedDurationDays;
    }

    /**
     * Set the number of days the access request should be requested for.
     * @param RequestedDurationDays Requested duration days
     */
    public void setRequestedDurationDays(Long RequestedDurationDays) {
        this.RequestedDurationDays = RequestedDurationDays;
    }

    /**
     * Get the number of hours the access request should be requested for.
     * @return Long
     */
    public Long getRequestedDurationHours() {
        return RequestedDurationHours;
    }

    /**
     * Set the number of hours the access request should be requested for.
     * @param RequestedDurationHours Requested duration hours
     */
    public void setRequestedDurationHours(Long RequestedDurationHours) {
        this.RequestedDurationHours = RequestedDurationHours;
    }

    /**
     * Get the number of minutes the access request should be requested for.
     * @return Long
     */
    public Long getRequestedDurationMinutes() {
        return RequestedDurationMinutes;
    }

    /**
     * Set the number of minutes the access request should be requested for.
     * @param RequestedDurationMinutes Requested duration minutes
     */
    public void setRequestedDurationMinutes(Long RequestedDurationMinutes) {
        this.RequestedDurationMinutes = RequestedDurationMinutes;
    }
    
    @Override
    public String toJson() {
        return new StringBuffer("{")
                .append(Utils.toJsonString("AccountId", this.AccountId, false))
                .append(Utils.toJsonString("SystemId", this.AssetId, true))
                .append(Utils.toJsonString("AccessRequestType", this.AccessType == null ? null : this.AccessType.toString(), true))
                .append(Utils.toJsonString("IsEmergency", this.IsEmergency, true))
                .append(Utils.toJsonString("ReasonCodeId", this.ReasonCodeId, true))
                .append(Utils.toJsonString("ReasonComment", this.ReasonComment, true))
                .append(Utils.toJsonString("RequestedDurationDays", this.RequestedDurationDays, true))
                .append(Utils.toJsonString("RequestedDurationHours", this.RequestedDurationHours, true))
                .append(Utils.toJsonString("RequestedDurationMinutes", this.RequestedDurationMinutes, true))
                .append(Utils.toJsonString("RequestedFor", this.RequestedFor == null ? null : this.RequestedFor.toString(), true))
                .append(Utils.toJsonString("TicketNumber", this.TicketNumber, true))
                .append(Utils.toJsonString("AccountName", this.AccountName, true))
                .append(Utils.toJsonString("SystemName", this.AssetName, true))
                .append(Utils.toJsonString("ForUserId", this.ForUserId, true))
                .append(Utils.toJsonString("ForUser", this.ForUserName, true))
                .append(Utils.toJsonString("ForProvider", this.ForUserIdentityProvider, true))
                .append(Utils.toJsonString("ReasonCode", this.ReasonCode, true))
                .append("}").toString();
    }
}

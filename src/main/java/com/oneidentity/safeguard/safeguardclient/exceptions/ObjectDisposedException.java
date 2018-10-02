package com.oneidentity.safeguard.safeguardclient.exceptions;

public class ObjectDisposedException extends Exception {

    public ObjectDisposedException(String msg) {
        super(msg);
    }

    @Override
    public String getLocalizedMessage() {
        return getMessage();
    }

    @Override
    public String getMessage() {
        String retVal = "";
        if (null != super.getMessage()) {
            retVal = super.getMessage();
        }
        return retVal;
    }
    private static final long serialVersionUID = 1L;
    private int status = 500;

    public ObjectDisposedException() {
        super();
    }

    public ObjectDisposedException(Exception cause, int status) {
        super(cause);
        this.status = status;
    }

    public ObjectDisposedException(String msg, int status) {
        super(msg);
        this.status = status;
    }
    
    public ObjectDisposedException(String msg, Exception cause, int status) {
        super(msg, cause);
        this.status = status;
    }

    public int getStatus() {
        return status;
    }

    public void setStatus(int status) {
        this.status = status;
    }

}

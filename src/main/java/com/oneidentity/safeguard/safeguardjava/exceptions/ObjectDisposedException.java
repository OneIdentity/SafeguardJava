package com.oneidentity.safeguard.safeguardjava.exceptions;

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

    public ObjectDisposedException() {
        super();
    }
}

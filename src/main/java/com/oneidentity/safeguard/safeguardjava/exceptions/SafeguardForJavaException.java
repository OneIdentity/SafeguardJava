package com.oneidentity.safeguard.safeguardjava.exceptions;

public class SafeguardForJavaException extends Exception {

    public SafeguardForJavaException(String msg) {
        super(msg);
    }
    
    public SafeguardForJavaException(String msg, Exception cause) {
        super(msg, cause);
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

    public SafeguardForJavaException() {
        super();
    }
}

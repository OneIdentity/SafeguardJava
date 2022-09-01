package com.oneidentity.safeguard.safeguardjava.data;

import com.oneidentity.safeguard.safeguardjava.exceptions.SafeguardForJavaException;

public interface JsonObject {

    String toJson() throws SafeguardForJavaException;
}

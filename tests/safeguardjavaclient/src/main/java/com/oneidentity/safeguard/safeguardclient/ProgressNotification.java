package com.oneidentity.safeguard.safeguardclient;

import com.oneidentity.safeguard.safeguardjava.IProgressCallback;
import com.oneidentity.safeguard.safeguardjava.data.TransferProgress;

public class ProgressNotification implements IProgressCallback {

    @Override
    public void checkProgress(TransferProgress transferProgress) {
        System.out.println(String.format("\tBytes transfered %d done", transferProgress.getPercentComplete()));
    }
    
}

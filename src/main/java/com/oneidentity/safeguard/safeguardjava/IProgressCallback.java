package com.oneidentity.safeguard.safeguardjava;

import com.oneidentity.safeguard.safeguardjava.data.TransferProgress;

public interface IProgressCallback {
    public void checkProgress(TransferProgress transferProgress);
}

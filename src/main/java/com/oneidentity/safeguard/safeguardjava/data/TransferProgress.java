package com.oneidentity.safeguard.safeguardjava.data;

public class TransferProgress {
    private long BytesTransferred;
    private long BytesTotal;

    public long getBytesTransferred() {
        return BytesTransferred;
    }

    public void setBytesTransferred(long BytesTransferred) {
        this.BytesTransferred = BytesTransferred;
    }

    public long getBytesTotal() {
        return BytesTotal;
    }

    public void setBytesTotal(long BytesTotal) {
        this.BytesTotal = BytesTotal;
    }
    
    public int getPercentComplete() {
        return BytesTotal == 0 ? 0 : (int)((double)BytesTransferred / BytesTotal * 100);
    }
}

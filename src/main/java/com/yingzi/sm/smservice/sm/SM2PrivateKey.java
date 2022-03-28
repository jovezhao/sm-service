package com.yingzi.sm.smservice.sm;

import java.security.PrivateKey;

public class SM2PrivateKey implements PrivateKey {
    private byte[] key;

    public SM2PrivateKey(byte[] key) {
        this.key = key;
    }

    @Override
    public String getAlgorithm() {
        return "SM2";
    }

    @Override
    public String getFormat() {
        return Utils.byteToHex(key);
    }

    @Override
    public byte[] getEncoded() {
        return key;
    }

}
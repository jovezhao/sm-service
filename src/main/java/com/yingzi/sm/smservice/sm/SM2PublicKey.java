package com.yingzi.sm.smservice.sm;

import java.security.PublicKey;

public class SM2PublicKey implements PublicKey {
    private byte[] key;

    public SM2PublicKey(byte[] key) {
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
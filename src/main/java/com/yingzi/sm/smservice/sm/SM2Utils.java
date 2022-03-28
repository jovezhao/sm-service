package com.yingzi.sm.smservice.sm;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECPoint;


public class SM2Utils {
    public SM2Utils() {
    }

    public static KeyPair generateKeyPair() {
        SM2 sm2 = SM2.Instance();

        AsymmetricCipherKeyPair key = sm2.ecc_key_pair_generator.generateKeyPair();
        ECPrivateKeyParameters ecpriv = (ECPrivateKeyParameters) key.getPrivate();
        ECPublicKeyParameters ecpub = (ECPublicKeyParameters) key.getPublic();
        BigInteger privateKey = ecpriv.getD();
        ECPoint publicKey = ecpub.getQ();
        KeyPair keyPair = new KeyPair(new SM2PublicKey(publicKey.getEncoded()),
                new SM2PrivateKey(privateKey.toByteArray()));
        // System.out.println("公钥: " + Utils.byteToHex(publicKey.getEncoded()));
        // System.out.println("私钥: " + Utils.byteToHex(privateKey.toByteArray()));
        return keyPair;
    }

    public static String encrypt(byte[] publicKey, byte[] data) throws IOException {
        if (publicKey != null && publicKey.length != 0) {
            if (data != null && data.length != 0) {
                byte[] source = new byte[data.length];
                System.arraycopy(data, 0, source, 0, data.length);
                Cipher cipher = new Cipher();
                SM2 sm2 = SM2.Instance();
                ECPoint userKey = sm2.ecc_curve.decodePoint(publicKey);
                ECPoint c1 = cipher.Init_enc(sm2, userKey);
                cipher.Encrypt(source);
                byte[] c3 = new byte[32];
                cipher.Dofinal(c3);
                return Utils.byteToHex(c1.getEncoded()) + Utils.byteToHex(source) + Utils.byteToHex(c3);
            } else {
                return null;
            }
        } else {
            return null;
        }
    }

    public static String decrypt(byte[] privateKey, byte[] encryptedData) throws IOException {
        if (privateKey != null && privateKey.length != 0) {
            if (encryptedData != null && encryptedData.length != 0) {
                String data = Utils.byteToHex(encryptedData);
                byte[] c1Bytes = Utils.hexToByte(data.substring(0, 130));
                int c2Len = encryptedData.length - 97;
                byte[] c2 = Utils.hexToByte(data.substring(130, 130 + 2 * c2Len));
                byte[] c3 = Utils.hexToByte(data.substring(130 + 2 * c2Len, 194 + 2 * c2Len));
                SM2 sm2 = SM2.Instance();
                BigInteger userD = new BigInteger(1, privateKey);
                ECPoint c1 = sm2.ecc_curve.decodePoint(c1Bytes);
                Cipher cipher = new Cipher();
                cipher.Init_dec(userD, c1);
                cipher.Decrypt(c2);
                cipher.Dofinal(c3);
                return new String(c2);
            } else {
                return null;
            }
        } else {
            return null;
        }
    }
}
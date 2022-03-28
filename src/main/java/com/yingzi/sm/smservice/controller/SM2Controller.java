package com.yingzi.sm.smservice.controller;

import java.io.IOException;
import java.security.KeyPair;

import com.yingzi.sm.smservice.sm.SM2Utils;
import com.yingzi.sm.smservice.sm.Utils;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import io.swagger.annotations.Api;

@RestController
@Api("SM2")
public class SM2Controller {

    @PostMapping("/generate")
    public KeyPair generate() {
        KeyPair keyPair = SM2Utils.generateKeyPair();
        return keyPair;
    }

    @PostMapping("/encrypt")
    public String encrypt(String publicKey, String data) throws IOException {
        byte[] sm2key = Utils.hexToByte(publicKey);
        return SM2Utils.encrypt(sm2key, data.getBytes());
    }

    @PostMapping("/decrypt")
    public String decrypt(String privateKey, String data) throws IOException {
        byte[] sm2key = Utils.hexToByte(privateKey);
        return SM2Utils.decrypt(sm2key, Utils.hexToByte(data));
    }

}

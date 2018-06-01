package com.example.juanperezdealgaba.sac;

public class BoringSSL {

    static{
        System.loadLibrary("BoringSSL");
    }

    public native double[] RSA();

    public native int[] AESCBC();

    public native int[] DH();

    public native double[] MD5();

    public native int[] AESCTR();

    public native int[] AESGCM();

    public native int[] AESOFB();

    public native int[] ECDH();
}

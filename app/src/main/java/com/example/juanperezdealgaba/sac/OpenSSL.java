package com.example.juanperezdealgaba.sac;

public class OpenSSL {

    static {
        System.loadLibrary("OpenSSL");
    }


    public native double[] RSA(int size);

    public native int[] AESCBC(int size);

    public native double[] DH();

    public native int[] ECDH();

    public native int[] MD5();

    public native int[] AESCTR();

    public native int[] AESGCM();

    public native int[] AESOFB();

}



package com.example.juanperezdealgaba.sac;

public class mbedTLS {

    static {
        System.loadLibrary("mbedTLS");
    }

    public native int[] RSA();

    public native int[] AESCBC(int blocksize);

    public native int[] MD5();

    public native int[] DH();

    public native int[] ECDH();

    public native int[] AESCTR(int blocksize);

    public native int[] AESGCM(int blocksize);

}
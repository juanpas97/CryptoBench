package com.example.juanperezdealgaba.sac;

public class mbedTLS {

    static {
        System.loadLibrary("mbedTLS");
    }

    public native int[] RSA(int blocksize);

    public native int[] AESCBC(int blocksize);

    public native int[] MD5(int blocksize);

    public native int[] DH();

    public native int[] ECDH();

    public native int[] AESCTR(int blocksize);

    public native int[] AESGCM(int blocksize);

}
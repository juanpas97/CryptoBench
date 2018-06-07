package com.example.juanperezdealgaba.sac;

public class BoringSSL {

    static{
        System.loadLibrary("BoringSSL");
    }

    public native int[] RSA(int blocksize);

    public native int[] AESCBC(int blocksize);

    public native int[] DH();

    public native int[] MD5(int blocksize);

    public native int[] AESCTR(int blocksize);

    public native int[] AESGCM(int blocksize);

    public native int[] AESOFB(int blocksize);

    public native int[] ECDH();
}

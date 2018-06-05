package com.example.juanperezdealgaba.sac;

public class WolfCrypt {

    static {
        System.loadLibrary("wolfssl");
        System.loadLibrary("wolfssljni");
    }


    public native int[] DH();
    public native int[] AESCBC();
    public native int[] MD5();
    public native int[] RSA();
    public native int[] AESCTR();
    public native int[] AESGCM();
    public native int[] ECDH();
    ;
}

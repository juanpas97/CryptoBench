package com.example.juanperezdealgaba.sac;

public class WolfCrypt {

    static {
        System.loadLibrary("wolfssl");
        System.loadLibrary("wolfssljni");
    }


    public native double[] DH();
    public native int[] AESCBC();
    public native double[] MD5();
    public native double[] RSA();
    public native int[] AESCTR();
    public native int[] AESGCM();
    public native int[] ECDH();
}

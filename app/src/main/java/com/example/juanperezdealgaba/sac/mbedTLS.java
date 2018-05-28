package com.example.juanperezdealgaba.sac;

public class mbedTLS {

    static{
        System.loadLibrary("mbedTLS");
    }

    public native double[] RSA();

    public native double[] AESCBC();

    public native double[] MD5();

    public native double[] DH();

    public native int[] AESCTR();
}

package com.example.juanperezdealgaba.sac;

public class mbedTLS {

    static{
        System.loadLibrary("mbedTLS");
    }

    public native double[] RSA();

    public native double[] AES();

    public native double[] MD5();

    //public native void DH();
}

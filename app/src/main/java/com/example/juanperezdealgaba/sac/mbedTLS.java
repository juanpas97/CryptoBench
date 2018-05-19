package com.example.juanperezdealgaba.sac;

public class mbedTLS {

    static{
        System.loadLibrary("mbedTLS");
    }

    public native int RSA();

    public native int AES();

    public native void MD5();

    //public native void DH();
}

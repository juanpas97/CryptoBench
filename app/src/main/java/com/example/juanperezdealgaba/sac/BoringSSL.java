package com.example.juanperezdealgaba.sac;

public class BoringSSL {

    static{
        System.loadLibrary("BoringSSL");
    }

    public native double[] RSA();

    public native double[] AES();

    public native double[] DH();

    public native int MD5();
}

package com.example.juanperezdealgaba.sac;

public class BoringSSL {

    static{
        System.loadLibrary("BoringSSL");
    }

    public native int RSA();

    public native int AES();

    //public native int DH();

    public native int MD5();
}

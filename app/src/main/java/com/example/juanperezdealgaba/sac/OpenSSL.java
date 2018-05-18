package com.example.juanperezdealgaba.sac;

public class OpenSSL {

    static {
        System.loadLibrary("OpenSSL");
    }


    public native int RSA();

    public native int AES();

    public native int DH();

    public native int MD5();


}



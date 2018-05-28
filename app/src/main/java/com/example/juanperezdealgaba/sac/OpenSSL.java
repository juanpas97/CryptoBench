package com.example.juanperezdealgaba.sac;

public class OpenSSL {

    static {
        System.loadLibrary("OpenSSL");
    }


    public native double[] RSA(int size);

    public native double[] AESCBC(int size);

    public native double[] DH();

    public native double[] MD5();


}



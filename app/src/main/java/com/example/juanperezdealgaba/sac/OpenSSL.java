package com.example.juanperezdealgaba.sac;

public class OpenSSL {

    static {
        System.loadLibrary("OpenSSL");
    }


    public native double[] RSA(int size);

    public native double[] AES(int size);

    public native int DH();

    public native double[] MD5();


}



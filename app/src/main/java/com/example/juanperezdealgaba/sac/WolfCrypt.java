package com.example.juanperezdealgaba.sac;

public class WolfCrypt {

    static {
        System.loadLibrary("wolfssl");
        System.loadLibrary("wolfssljni");
    }


    public native double[] DH();
    public native double[] AES();
    public native double[] MD5();
}

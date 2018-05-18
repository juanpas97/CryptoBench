package com.example.juanperezdealgaba.sac;

public class WolfCrypt {

    static {
        System.loadLibrary("wolfssl");
        System.loadLibrary("wolfssljni");
    }


    public native void DH();
    public native void AES();
    public native void MD5();
}

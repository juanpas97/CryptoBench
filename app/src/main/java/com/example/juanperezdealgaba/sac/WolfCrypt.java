package com.example.juanperezdealgaba.sac;

public class WolfCrypt {

    static {
        System.loadLibrary("wolfssl");
        System.loadLibrary("wolfssljni");
    }


    public native int[] DH(int rep_agree);
    public native int[] AESCBC(int blocksize);
    public native int[] MD5(int blocksize,int rep_hash);
    public native int[] RSA(int blocksize,int rep_rsa);
    public native int[] AESCTR(int blocksize);
    public native int[] AESGCM(int blocksize);
    public native int[] ECDH(int rep_agree);
    ;
}

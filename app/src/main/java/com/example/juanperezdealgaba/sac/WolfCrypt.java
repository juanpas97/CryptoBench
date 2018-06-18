package com.example.juanperezdealgaba.sac;

public class WolfCrypt {

    static {
        System.loadLibrary("wolfssl");
        System.loadLibrary("wolfssljni");
    }


    public native int[] DH(int rep_agree);
    public native void DHTime(int rep_key,int rep_agree,String title);

    public native int[] AESCBC(int blocksize,int rep_aes);
    public native void AESCBCTime(int blocksize,int rep_key,int rep_aes,String title);

    public native int[] MD5(int blocksize,int rep_hash);
    public native void MD5Time(int blocksize,int rep_hash,String title);

    public native int[] RSA(int blocksize,int rep_rsa);
    public native void RSATime(int blocksize,int rep_key,int rep_rsa,String title);

    public native int[] AESCTR(int blocksize,int rep_aes);
    public native void AESCTRTime(int blocksize,int rep_key,int rep_aes,String title);

    public native int[] AESGCM(int blocksize,int rep_aes);
    public native void AESGCMTime(int blocksize,int rep_key,int rep_aes,String title);


    public native int[] ECDH(int rep_agree);
    public native void ECDHTime(int rep_key,int rep_agree,String title);
}

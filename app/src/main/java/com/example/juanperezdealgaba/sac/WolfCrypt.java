package com.example.juanperezdealgaba.sac;

public class WolfCrypt {

    static {
        System.loadLibrary("wolfssl");
        System.loadLibrary("wolfssljni");
    }


    public native  void DH(int rep_agree,int rep_total);
    public native void DHTime(int rep_key,int rep_agree,String title,int rep_total);

    public native void AESCBC(int blocksize,int rep_aes,int rep_total);
    public native void AESCBCTime(int blocksize,int rep_key,int rep_aes,String title, int rep_total);

    public native void MD5(int blocksize,int rep_hash,int repetitions);
    public native void MD5Time(int blocksize,int rep_hash,String title, int rep_total);

    public native void RSA(int blocksize,int rep_rsa,int rep_total);
    public native void RSATime(int blocksize,int rep_key,int rep_rsa,String title,int rep_total);

    public native void AESCTR(int blocksize,int rep_aes,int rep_total);
    public native void AESCTRTime(int blocksize,int rep_key,int rep_aes,String title,int rep_total);

    public native void AESGCM(int blocksize,int rep_aes,int rep_total);
    public native void AESGCMTime(int blocksize,int rep_key,int rep_aes,String title,int rep_total);

    public native void ECDH(int rep_agree,int rep_total);
    public native void ECDHTime(int rep_key,int rep_agree,String title,int rep_total);

    public native int setTimer();

}

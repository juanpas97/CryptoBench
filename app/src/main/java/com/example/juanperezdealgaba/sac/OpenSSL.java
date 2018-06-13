package com.example.juanperezdealgaba.sac;

public class OpenSSL {

    static {
        System.loadLibrary("OpenSSL");
    }


    public native int[] RSA(int blocksize,int rep_rsa);

    public native void RSATime(int blocksize,int rep_key,int rep_rsa);

    public native int[] AESCBC(int blocksize,int rep_aes);

    public native void AESCBCTime(int blocksize,int rep_key,int rep_aes);

    public native int[] DH(int rep_agree);

    public native void DHTime(int rep_key ,int rep_agree);

    public native int[] ECDH(int rep_Agree);

    public native void ECDHTime(int rep_key, int rep_Agree);

    public native int[] MD5(int blocksize,int rep_hash);

    public native void MD5Time(int blocksize,int rep_hash);

    public native int[] AESCTR(int blocksize,int rep_aes);

    public native void AESCTRTime(int blocksize,int rep_key,int rep_aes);

    public native int[] AESGCM(int blocksize,int rep_aes);

    public native void AESGCMTime(int blocksize,int rep_key,int rep_aes);

    public native int[] AESOFB(int blocksize,int rep_aes);

    public native void AESOFBTime(int blocksize,int rep_key,int rep_aes);

}



package com.example.juanperezdealgaba.sac;

import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.util.encoders.DecoderException;
import org.spongycastle.util.encoders.Hex;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AESGCM {

    public  void testGCM() throws NoSuchAlgorithmException,NoSuchProviderException,NoSuchPaddingException,InvalidKeyException,InvalidAlgorithmParameterException,IllegalBlockSizeException,
            BadPaddingException,DecoderException{

        Security.addProvider(new BouncyCastleProvider());

        byte[] keyBytes = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
                0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

        byte[] ivBytes = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x01 };

        byte[] plaintext = Hex.decode("d9313225f88406e5a55909c5aff5269a");

        Key key;
        Cipher in, out;

        key = new SecretKeySpec(keyBytes, "AES");

        in = Cipher.getInstance("AES/GCM/NoPadding", "SC");
        out = Cipher.getInstance("AES/GCM/NoPadding", "SC");

        in.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(ivBytes));

        System.out.println("Plaintext");
        for(int i = 0; i < plaintext.length;i++){
            System.out.println(Integer.toHexString(plaintext[i]));
        }


        byte[] enc = in.doFinal(plaintext);

        System.out.println("Encrypted");
        for(int i = 0; i < enc.length;i++){
            System.out.println(Integer.toHexString(enc[i]));
        }


        out.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(ivBytes));

        byte[] dec = out.doFinal(enc);
        System.out.println("Decrypted");
        for(int i = 0; i < dec.length;i++){
            System.out.println(Integer.toHexString(dec[i]));
        }


    }
}

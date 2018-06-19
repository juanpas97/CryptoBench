package com.example.juanperezdealgaba.sac;

import android.widget.TextView;

import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.util.encoders.DecoderException;
import org.spongycastle.util.encoders.Hex;

import java.io.FileWriter;
import java.io.IOException;
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

public class AESCBC {

    public void testCBC() throws NoSuchAlgorithmException,NoSuchProviderException,NoSuchPaddingException,InvalidKeyException,InvalidAlgorithmParameterException,IllegalBlockSizeException,
            BadPaddingException,DecoderException {

        Security.addProvider(new BouncyCastleProvider());

        byte[] keyBytes = new byte[] { 0x2b, 0x7e, 0x15, 0x16, 0x28, (byte)0xae,(byte) 0xd2, (byte)0xa6,(byte) 0xab, (byte)0xf7,
                0x15, (byte) 0x88,
                0x09, (byte)0xcf, 0x4f, 0x3c};

        byte[] ivBytes = new byte[] {  0x09, (byte) 0xcf,0x15,(byte) 0x88, 0x4f, 0x3c,0x2b, 0x7e, 0x15,(byte)0xae,0x16, 0x28,(byte) 0xd2,(byte) 0xa6,(byte) 0xab,(byte) 0xf7 };

        byte[] plaintext = Hex.decode("d9313225f88406e5a55909c5aff5269a");

        Key key;
        Cipher in, out;

        key = new SecretKeySpec(keyBytes, "AES");

        in = Cipher.getInstance("AES/CBC/NoPadding", "SC");
        out = Cipher.getInstance("AES/CBC/NoPadding", "SC");

        in.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(ivBytes));

        /*System.out.println("Plaintext");
        for(int i = 0; i < plaintext.length;i++){
            System.out.println(Integer.toHexString(plaintext[i]));
        }*/


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

    public void testCBC(FileWriter writer, TextView Results, int blocksize, int rep_aes) throws NoSuchAlgorithmException,NoSuchProviderException,NoSuchPaddingException,InvalidKeyException,InvalidAlgorithmParameterException,IllegalBlockSizeException,
            BadPaddingException,DecoderException {

        try {

            Security.addProvider(new BouncyCastleProvider());

            byte[] keyBytes = new byte[]{0x2b, 0x7e, 0x15, 0x16, 0x28, (byte) 0xae, (byte) 0xd2, (byte) 0xa6, (byte) 0xab, (byte) 0xf7,
                    0x15, (byte) 0x88,
                    0x09, (byte) 0xcf, 0x4f, 0x3c};

            byte[] ivBytes = new byte[]{0x09, (byte) 0xcf, 0x15, (byte) 0x88, 0x4f, 0x3c, 0x2b, 0x7e, 0x15, (byte) 0xae, 0x16, 0x28, (byte) 0xd2, (byte) 0xa6, (byte) 0xab, (byte) 0xf7};

            RandomStringGenerator string = new RandomStringGenerator();
            String input = string.generateRandomString(blocksize);

            byte[] plaintext = input.getBytes();

            Key key;
            Cipher in, out;

            key = new SecretKeySpec(keyBytes, "AES");

            in = Cipher.getInstance("AES/CBC/NoPadding", "SC");
            out = Cipher.getInstance("AES/CBC/NoPadding", "SC");

            in.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(ivBytes));
            out.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(ivBytes));

        /*System.out.println("Plaintext");
        for(int i = 0; i < plaintext.length;i++){
            System.out.println(Integer.toHexString(plaintext[i]));
        }*/
            for(int i = 0; i < rep_aes; i++) {
                long start = System.nanoTime();
                byte[] enc = in.doFinal(plaintext);
                long end = System.nanoTime();
                long microseconds = (end - start) / 1000;
                writer.write("Time to encrypt: " + microseconds + " ms" + "\n");

                //System.out.println("Encrypted");
                //for (int i = 0; i < enc.length; i++) {
                //    System.out.println(Integer.toHexString(enc[i]));
                //}

                start = System.nanoTime();
                byte[] dec = out.doFinal(enc);
                end = System.nanoTime();
                microseconds = (end - start) / 1000;
                writer.write("Time to decrypt: " + microseconds + " ms" + "\n");
                System.out.println("Decrypted");
                //for (int i = 0; i < dec.length; i++) {
                //  System.out.println(Integer.toHexString(dec[i]));
                //}
            }
        }catch (IOException i){
            throw new RuntimeException(i);
        }


    }


    public void testCBCTime(FileWriter writer, TextView Results, int blocksize, long rep_key,long rep_aes) throws NoSuchAlgorithmException,NoSuchProviderException,NoSuchPaddingException,InvalidKeyException,InvalidAlgorithmParameterException,IllegalBlockSizeException,
            BadPaddingException,DecoderException {

        try {

            Security.addProvider(new BouncyCastleProvider());

            byte[] keyBytes = new byte[]{0x2b, 0x7e, 0x15, 0x16, 0x28, (byte) 0xae, (byte) 0xd2, (byte) 0xa6, (byte) 0xab, (byte) 0xf7,
                    0x15, (byte) 0x88,
                    0x09, (byte) 0xcf, 0x4f, 0x3c};

            byte[] ivBytes = new byte[]{0x09, (byte) 0xcf, 0x15, (byte) 0x88, 0x4f, 0x3c, 0x2b, 0x7e, 0x15, (byte) 0xae, 0x16, 0x28, (byte) 0xd2, (byte) 0xa6, (byte) 0xab, (byte) 0xf7};

            RandomStringGenerator string = new RandomStringGenerator();
            String input = string.generateRandomString(blocksize);

            byte[] plaintext = input.getBytes();
            Key key;
            Cipher in, out;

            in = Cipher.getInstance("AES/CBC/NoPadding", "SC");
            out = Cipher.getInstance("AES/CBC/NoPadding", "SC");
            int repetitions = 0;
            long finishTime = System.currentTimeMillis()+rep_key;
            while(System.currentTimeMillis() <= finishTime) {

                long start = System.nanoTime();
                key = new SecretKeySpec(keyBytes, "AES");

                in.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(ivBytes));
                out.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(ivBytes));
                long end = System.nanoTime();
                long microseconds = (end - start) / 1000;
                writer.write("Time to set key: " + microseconds + " ms\n" );
                repetitions += 1;
            }
            writer.write("Times set key: " + repetitions + "\n");
            byte[] enc = new byte[0];
            repetitions = 0;
            finishTime = System.currentTimeMillis() + rep_aes;
            while(System.currentTimeMillis() <= finishTime) {
                long start = System.nanoTime();
                enc = in.doFinal(plaintext);
                long end = System.nanoTime();
                long microseconds = (end - start) / 1000;
                writer.write("Time to encrypt: " + microseconds + " ms" + "\n");
                repetitions +=1;
            }
            writer.write("Times performed encryption" + repetitions + "\n");
            repetitions = 0;
            finishTime = System.currentTimeMillis() + rep_aes;
            while(System.currentTimeMillis() <= finishTime) {
                long start = System.nanoTime();
                byte[] dec = out.doFinal(enc);
                long end = System.nanoTime();
                long microseconds = (end - start) / 1000;
                writer.write("Time to decrypt: " + microseconds + " ms" + "\n");
                System.out.println("Decrypted");
                //for (int i = 0; i < dec.length; i++) {
                //  System.out.println(Integer.toHexString(dec[i]));
                //}
                repetitions +=1;
            }
            writer.write("Times performed decryption" + repetitions + "\n");
        }catch (IOException i){
            throw new RuntimeException(i);
        }


    }
}

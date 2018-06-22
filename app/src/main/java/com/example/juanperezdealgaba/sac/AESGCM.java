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
import java.util.Random;

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

        byte[] keyBytes = new byte[] { 0x2b, 0x7e, 0x15, 0x16, 0x28, (byte)0xae,(byte) 0xd2, (byte)0xa6,(byte) 0xab, (byte)0xf7,
                0x15, (byte) 0x88,
                0x09, (byte)0xcf, 0x4f, 0x3c};

        byte[] ivBytes = new byte[] {  0x09, (byte) 0xcf,0x15,(byte) 0x88, 0x4f, 0x3c,0x2b, 0x7e, 0x15,(byte)0xae,0x16, 0x28,(byte) 0xd2,(byte) 0xa6,(byte) 0xab,(byte) 0xf7 };


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

    public  void testGCM(FileWriter writer, TextView results, int blocksize,int rep_aes,int total_rep) throws NoSuchAlgorithmException,NoSuchProviderException,NoSuchPaddingException,InvalidKeyException,InvalidAlgorithmParameterException,IllegalBlockSizeException,
            BadPaddingException,DecoderException{
        Security.addProvider(new BouncyCastleProvider());

        byte[] keyBytes = new byte[]{0x2b, 0x7e, 0x15, 0x16, 0x28, (byte) 0xae, (byte) 0xd2, (byte) 0xa6, (byte) 0xab, (byte) 0xf7,
                0x15, (byte) 0x88,
                0x09, (byte) 0xcf, 0x4f, 0x3c};

        byte[] ivBytes = new byte[]{0x09, (byte) 0xcf, 0x15, (byte) 0x88, 0x4f, 0x3c, 0x2b, 0x7e, 0x15, (byte) 0xae, 0x16, 0x28, (byte) 0xd2, (byte) 0xa6, (byte) 0xab, (byte) 0xf7};

        RandomStringGenerator string = new RandomStringGenerator();
        String input = string.generateRandomString(blocksize);

        byte[] plaintext = input.getBytes();
        Key key = null;
        Cipher in, out;

        in = Cipher.getInstance("AES/CBC/NoPadding", "SC");
        out = Cipher.getInstance("AES/CBC/NoPadding", "SC");


        byte[] enc = new byte[0];
        for (int i = 0; i < total_rep; i++) {
            key = new SecretKeySpec(keyBytes, "AES");
            in.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(ivBytes));
            out.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(ivBytes));
            int repetitions = 0;

            long start = System.nanoTime();
            for (int j = 0; j < rep_aes - 1; j++) {
                    enc = in.update(plaintext);
                    repetitions += 1;
                }
                repetitions += 1;
                enc = in.doFinal(plaintext);

                long end = System.nanoTime();
                long elapsedTime = end - start;
                double seconds = (double) elapsedTime / 1000000000.0;

                try {
                    writer.write("repetitions encrypt:" + repetitions + "\n");
                    writer.write("Seconds:" + seconds + "\n");
                    writer.write("Time to encrypt: " + (repetitions * (blocksize)) / seconds + " byte/seconds" + "\n");
                } catch (IOException e) {
                    e.printStackTrace();
                }

        }
        byte[] dec;
        for (int i = 0; i < total_rep; i++) {
            int repetitions = 0;
            long start = System.nanoTime();

            for (int j = 0; j < rep_aes - 1; j++) {
                    dec = out.update(enc);
                    repetitions += 1;
            }
            repetitions += 1;
            dec = out.doFinal(enc);
                long end = System.nanoTime();
                long elapsedTime = end - start;
                double seconds = (double) elapsedTime / 1000000000.0;

                try {
                    writer.write("repetitions decrypt:" + repetitions + "\n");
                    writer.write("Seconds:" + seconds + "\n");
                    writer.write("Time to decrypt: " + (repetitions * (blocksize)) / seconds + " byte/seconds" + "\n");

                } catch (IOException e) {
                    e.printStackTrace();
                }

            System.out.println("Decrypted");
        }

    }

    public  void testGCMTime(FileWriter writer, TextView results, int blocksize,long rep_key ,long rep_aes,int total_rep) throws NoSuchAlgorithmException,NoSuchProviderException,NoSuchPaddingException,InvalidKeyException,InvalidAlgorithmParameterException,IllegalBlockSizeException,
            BadPaddingException,DecoderException{
        Security.addProvider(new BouncyCastleProvider());

        byte[] keyBytes = new byte[]{0x2b, 0x7e, 0x15, 0x16, 0x28, (byte) 0xae, (byte) 0xd2, (byte) 0xa6, (byte) 0xab, (byte) 0xf7,
                0x15, (byte) 0x88,
                0x09, (byte) 0xcf, 0x4f, 0x3c};

        byte[] ivBytes = new byte[]{0x09, (byte) 0xcf, 0x15, (byte) 0x88, 0x4f, 0x3c, 0x2b, 0x7e, 0x15, (byte) 0xae, 0x16, 0x28, (byte) 0xd2, (byte) 0xa6, (byte) 0xab, (byte) 0xf7};

        RandomStringGenerator string = new RandomStringGenerator();
        String input = string.generateRandomString(blocksize);

        byte[] plaintext = input.getBytes();
        Key key = null;
        Cipher in, out;

        in = Cipher.getInstance("AES/CBC/NoPadding", "SC");
        out = Cipher.getInstance("AES/CBC/NoPadding", "SC");
        int repetitions = 0;
        long finishTime = System.currentTimeMillis()+rep_key;
        long start = System.nanoTime();
        while(System.currentTimeMillis() <= finishTime) {

            key = new SecretKeySpec(keyBytes, "AES");

            in.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(ivBytes));
            out.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(ivBytes));

            repetitions += 1;
        }
        long end = System.nanoTime();
        long elapsedTime = end - start;
        double seconds = (double)elapsedTime / 1000000000.0;

        try {
            writer.write("Time setting key: " + (repetitions/seconds) + " times/second" + "\n");
        } catch (IOException e) {
            e.printStackTrace();
        }


        byte[] enc = new byte[0];
        for (int i = 0; i < total_rep; i++) {
            in.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(ivBytes));
            out.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(ivBytes));
            repetitions = 0;
            finishTime = System.currentTimeMillis() + rep_aes;
            start = System.nanoTime();
            while (System.currentTimeMillis() <= finishTime) {
                enc = in.update(plaintext);
                repetitions += 1;
            }

            enc = in.doFinal(plaintext);
            end = System.nanoTime();
            elapsedTime = end - start;
            seconds = (double) elapsedTime / 1000000000.0;

            try {
                writer.write("repetitions encrypt:" + repetitions + "\n" );
                writer.write("Seconds:" + seconds + "\n" );
                writer.write("Time to encrypt: " + (repetitions * (blocksize)) / seconds + " byte/seconds" + "\n");
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        byte[] dec;
        for (int i = 0; i < total_rep; i++) {
            repetitions = 0;
            start = System.nanoTime();
            finishTime = System.currentTimeMillis() + rep_aes;
            while (System.currentTimeMillis() <= finishTime) {
                dec = out.update(enc);
                repetitions += 1;
            }
            dec = out.doFinal(enc);
            end = System.nanoTime();
            elapsedTime = end - start;
            seconds = (double) elapsedTime / 1000000000.0;

            try {
                writer.write("repetitions decrypt:" + repetitions + "\n" );
                writer.write("Seconds:" + seconds + "\n" );
                writer.write("Time to decrypt: " + (repetitions * (blocksize)) / seconds + " byte/seconds" + "\n");

            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        System.out.println("Decrypted");


    }
}

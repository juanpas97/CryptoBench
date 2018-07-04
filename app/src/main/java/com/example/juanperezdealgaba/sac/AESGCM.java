package com.example.juanperezdealgaba.sac;

import android.widget.TextView;

import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.util.encoders.DecoderException;
import org.spongycastle.util.encoders.Hex;

import java.io.FileWriter;
import java.io.IOException;
import java.math.BigDecimal;
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



    public  void testGCM(FileWriter writer, TextView results, int blocksize,int rep_aes,int total_rep) throws NoSuchAlgorithmException,NoSuchProviderException,NoSuchPaddingException,InvalidKeyException,InvalidAlgorithmParameterException,IllegalBlockSizeException,
            BadPaddingException,DecoderException{
        Security.addProvider(new BouncyCastleProvider());

        Keys key_st = new Keys();

        byte[] keyBytes = key_st.returnAesKey();

        byte[] ivBytes = key_st.returnIV();

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
            double result = ((double)repetitions * (blocksize)) / seconds;


            try {
                    writer.write("repetitions encrypt:" + repetitions + "\n");
                    writer.write("Seconds:" + seconds + "\n");
                    writer.write("Time to encrypt: " + new BigDecimal(result).toPlainString() + " byte/seconds" + "\n");
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
            double result = ((double)repetitions * (blocksize)) / seconds;


            try {
                    writer.write("repetitions decrypt:" + repetitions + "\n");
                    writer.write("Seconds:" + seconds + "\n");
                    writer.write("Time to decrypt: " + new BigDecimal(result).toPlainString() + " byte/seconds" + "\n");

                } catch (IOException e) {
                    e.printStackTrace();
                }

            System.out.println("Decrypted");
        }

    }

    public  void testGCMTime(FileWriter writer, TextView results, int blocksize,long rep_key ,long rep_aes,int total_rep) throws NoSuchAlgorithmException,NoSuchProviderException,NoSuchPaddingException,InvalidKeyException,InvalidAlgorithmParameterException,IllegalBlockSizeException,
            BadPaddingException,DecoderException{
        Security.addProvider(new BouncyCastleProvider());

        Keys key_st = new Keys();

        byte[] keyBytes = key_st.returnAesKey();

        byte[] ivBytes = key_st.returnIV();

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

        bool_value.value = true;
        byte[] enc = new byte[0];
        for (int i = 0; i < total_rep; i++) {
            in.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(ivBytes));
            out.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(ivBytes));
            repetitions = 0;
            finishTime = System.currentTimeMillis() + rep_aes;
            start = System.nanoTime();
            while (bool_value.value) {
                enc = in.update(plaintext);
                repetitions += 1;
            }

            enc = in.doFinal(plaintext);
            end = System.nanoTime();
            elapsedTime = end - start;
            seconds = (double) elapsedTime / 1000000000.0;

            try {
                bool_value.value = true;
                writer.write("Repetitions:" + repetitions + "\n" );
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
            while (bool_value.value) {
                dec = out.update(enc);
                repetitions += 1;
            }
            dec = out.doFinal(enc);
            end = System.nanoTime();
            elapsedTime = end - start;
            seconds = (double) elapsedTime / 1000000000.0;

            try {
                bool_value.value = true;
                writer.write("Repetitions:" + repetitions + "\n" );
                writer.write("Seconds:" + seconds + "\n" );
                writer.write("Time to decrypt: " + (repetitions * (blocksize)) / seconds + " byte/seconds" + "\n");

            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        System.out.println("Decrypted");


    }
}

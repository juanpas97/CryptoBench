package com.example.juanperezdealgaba.sac;

import android.widget.TextView;

import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.util.encoders.DecoderException;
import org.spongycastle.util.encoders.Hex;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
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
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AESOFB {


    public void testOFB(FileWriter writer, TextView results, int blocksize, int rep_aes, int total_rep) throws NoSuchAlgorithmException,NoSuchProviderException,NoSuchPaddingException,InvalidKeyException,InvalidAlgorithmParameterException,IOException,DecoderException {
        Security.addProvider(new BouncyCastleProvider());

        RandomStringGenerator string = new RandomStringGenerator();
        String text = string.generateRandomString(blocksize);
        byte[] input = text.getBytes();
        byte[] keyBytes = new byte[] { 0x2b, 0x7e, 0x15, 0x16, 0x28, (byte)0xae,(byte) 0xd2, (byte)0xa6,(byte) 0xab, (byte)0xf7,
                0x15, (byte) 0x88,
                0x09, (byte)0xcf, 0x4f, 0x3c};

        byte[] ivBytes = new byte[] {  0x09, (byte) 0xcf,0x15,(byte) 0x88, 0x4f, 0x3c,0x2b, 0x7e, 0x15,(byte)0xae,0x16, 0x28,(byte) 0xd2,(byte) 0xa6,(byte) 0xab,(byte) 0xf7 };


        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");
        System.out.println("input : " + new String(input));

        // encryption pass

        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        for (int i = 0; i < total_rep; i++){
            int repetitions = 0;

            long start = System.nanoTime();
            for (int j = 0; j < rep_aes - 1; j++) {
                ByteArrayInputStream bIn = new ByteArrayInputStream(input);
                CipherInputStream cIn = new CipherInputStream(bIn, cipher);


                int ch;
                while ((ch = cIn.read()) >= 0) {
                    bOut.write(ch);
                }

            }

            long end = System.nanoTime();
            long elapsedTime = end - start;
            double seconds = (double) elapsedTime / 1000000000.0;

            try {
                writer.write("Time to encrypt: " + (repetitions * (blocksize)) / seconds + " byte/seconds" + "\n");
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        byte[] cipherText = bOut.toByteArray();


        // decryption pass

        for (int i = 0; i < total_rep; i++) {
            int repetitions = 0;
            long start = System.nanoTime();
            for (int j = 0; j < rep_aes - 1; i++) {
                bOut = new ByteArrayOutputStream();
                CipherOutputStream cOut = new CipherOutputStream(bOut, cipher);
                cOut.write(cipherText);
                cOut.close();
            }
            long end = System.nanoTime();
            long elapsedTime = end - start;
            double seconds = (double) elapsedTime / 1000000000.0;

            try {
                writer.write("Time to decrypt: " + (repetitions * (blocksize)) / seconds + " byte/seconds" + "\n");
            } catch (IOException e) {
                e.printStackTrace();
            }
            System.out.println("Decrypted");
            //for (int i = 0; i < dec.length; i++) {
            //  System.out.println(Integer.toHexString(dec[i]));
            //}

        }


    }

    public void testOFBTime(FileWriter writer, TextView results, int blocksize,long rep_key ,long rep_aes,int total_rep) throws NoSuchAlgorithmException,NoSuchProviderException,NoSuchPaddingException,InvalidKeyException,InvalidAlgorithmParameterException,IOException,DecoderException {
        RandomStringGenerator string = new RandomStringGenerator();
        String text = string.generateRandomString(blocksize);
        byte[] input = text.getBytes();
        byte[] keyBytes = new byte[] { 0x2b, 0x7e, 0x15, 0x16, 0x28, (byte)0xae,(byte) 0xd2, (byte)0xa6,(byte) 0xab, (byte)0xf7,
                0x15, (byte) 0x88,
                0x09, (byte)0xcf, 0x4f, 0x3c};

        byte[] ivBytes = new byte[] {  0x09, (byte) 0xcf,0x15,(byte) 0x88, 0x4f, 0x3c,0x2b, 0x7e, 0x15,(byte)0xae,0x16, 0x28,(byte) 0xd2,(byte) 0xa6,(byte) 0xab,(byte) 0xf7 };


        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
        Cipher cipher = Cipher.getInstance("AES/OFB/NoPadding", "BC");
        System.out.println("input : " + new String(input));

        // encryption pass

        int repetitions = 0;
        long finishTime = System.currentTimeMillis()+rep_key;
        long start_key = System.nanoTime();
        while(System.currentTimeMillis() <= finishTime) {
            cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
            cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);

            repetitions += 1;
        }
        long end_key = System.nanoTime();
        long elapsedTime_key = end_key - start_key;
        double seconds_key = (double)elapsedTime_key / 1000000000.0;

        try {
            writer.write("Time setting key: " + (repetitions/seconds_key) + " times/second" + "\n");
        } catch (IOException e) {
            e.printStackTrace();
        }
        ByteArrayOutputStream bOut;
        byte[] cipherText = new byte[0];
        for (int i = 0; i < total_rep; i++) {
            repetitions = 0;
            finishTime = System.currentTimeMillis() + rep_aes;
            long start = System.nanoTime();
            while (System.currentTimeMillis() <= finishTime) {

                ByteArrayInputStream bIn = new ByteArrayInputStream(input);
                CipherInputStream cIn = new CipherInputStream(bIn, cipher);
                bOut = new ByteArrayOutputStream();

                int ch;
                while ((ch = cIn.read()) >= 0) {
                    bOut.write(ch);
                }


                cipherText = bOut.toByteArray();
                repetitions += 1;
            }


            long end = System.nanoTime();
            long elapsedTime = end - start;
            double seconds = (double) elapsedTime / 1000000000.0;

            try {
                writer.write("Time to encrypt: " + (repetitions * (blocksize)) / seconds + " byte/seconds" + "\n");
                writer.write("Repetitions encrypt: " + repetitions + "\n");
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        for (int i = 0; i < total_rep; i++) {
            repetitions = 0;
            finishTime = System.currentTimeMillis() + rep_aes;
            long start = System.nanoTime();
            while (System.currentTimeMillis() <= finishTime) {
                // decryption pass


                bOut = new ByteArrayOutputStream();
                CipherOutputStream cOut = new CipherOutputStream(bOut, cipher);
                cOut.write(cipherText);
                cOut.close();

                repetitions += 1;
            }
            long end = System.nanoTime();
            long elapsedTime = end - start;
            double seconds = (double) elapsedTime / 1000000000.0;
            try {
                writer.write("Time to decrypt: " + (repetitions * (blocksize)) / seconds + " byte/seconds" + "\n");
                writer.write("Repetitions decrypt: " + repetitions + "\n");

            } catch (IOException e) {
                e.printStackTrace();
            }

        }
    }

}
package com.example.juanperezdealgaba.sac;

import android.widget.TextView;

import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.util.encoders.DecoderException;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

//Using this example http://www.java2s.com/Code/Java/Security/BasicIOexamplewithCTRusingAES.htm

public class AESCTR {

    public void testCTR() throws NoSuchAlgorithmException,NoSuchProviderException,NoSuchPaddingException,InvalidKeyException,InvalidAlgorithmParameterException,IOException,DecoderException {
            Security.addProvider(new BouncyCastleProvider());
            byte[] input = "example".getBytes();
            byte[] keyBytes = new byte[] { 0x2b, 0x7e, 0x15, 0x16, 0x28, (byte)0xae,(byte) 0xd2, (byte)0xa6,(byte) 0xab, (byte)0xf7,
                    0x15, (byte) 0x88,
                    0x09, (byte)0xcf, 0x4f, 0x3c};

            byte[] ivBytes = new byte[] {  0x09, (byte) 0xcf,0x15,(byte) 0x88, 0x4f, 0x3c,0x2b, 0x7e, 0x15,(byte)0xae,0x16, 0x28,(byte) 0xd2,(byte) 0xa6,(byte) 0xab,(byte) 0xf7 };


            SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
            IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
            Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding", "SC");
            System.out.println("input : " + new String(input));

            // encryption pass
            cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);

            ByteArrayInputStream bIn = new ByteArrayInputStream(input);
            CipherInputStream cIn = new CipherInputStream(bIn, cipher);
            ByteArrayOutputStream bOut = new ByteArrayOutputStream();

            int ch;
            while ((ch = cIn.read()) >= 0) {
                bOut.write(ch);
            }



            byte[] cipherText = bOut.toByteArray();

            System.out.println("cipher: " + new String(cipherText));

            // decryption pass
            cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
            bOut = new ByteArrayOutputStream();
            CipherOutputStream cOut = new CipherOutputStream(bOut, cipher);
            cOut.write(cipherText);
            cOut.close();
            System.out.println("plain : " + new String(bOut.toByteArray()));


        }

        public void testCTR(FileWriter writer, TextView results, int blocksize, int rep_aes) throws NoSuchAlgorithmException,NoSuchProviderException,NoSuchPaddingException,InvalidKeyException,InvalidAlgorithmParameterException,IOException,DecoderException {
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
                Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding", "SC");
                System.out.println("input : " + new String(input));

                // encryption pass

                cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
                cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);

                for(int i = 0; i < rep_aes; i++) {
                        long start = System.nanoTime();
                        ByteArrayInputStream bIn = new ByteArrayInputStream(input);
                        CipherInputStream cIn = new CipherInputStream(bIn, cipher);
                        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

                        int ch;
                        while ((ch = cIn.read()) >= 0) {
                                bOut.write(ch);
                        }

                        long end = System.nanoTime();
                        long microseconds = (end - start) / 1000;
                        writer.write("Time to encrypt: " + microseconds + " ms" + "\n");

                        byte[] cipherText = bOut.toByteArray();


                        // decryption pass

                        start = System.nanoTime();
                        bOut = new ByteArrayOutputStream();
                        CipherOutputStream cOut = new CipherOutputStream(bOut, cipher);
                        cOut.write(cipherText);
                        cOut.close();
                        end = System.nanoTime();
                        microseconds = (end - start) / 1000;
                        writer.write("Time to decrypt: " + microseconds + " ms" + "\n");
                }


        }


        public void testCTRTime(FileWriter writer, TextView results, int blocksize,long rep_key ,long rep_aes) throws NoSuchAlgorithmException,NoSuchProviderException,NoSuchPaddingException,InvalidKeyException,InvalidAlgorithmParameterException,IOException,DecoderException {
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
                Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding", "SC");
                System.out.println("input : " + new String(input));

                // encryption pass

                int repetitions = 0;
                long finishTime = System.currentTimeMillis()+rep_key;
                while(System.currentTimeMillis() <= finishTime) {
                        long start = System.nanoTime();
                        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
                        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);

                        long end = System.nanoTime();
                        long microseconds = (end - start) / 1000;
                        writer.write("Time to set key: " + microseconds + " ms\n" );
                        repetitions += 1;
                }
                writer.write("Times set key: " + repetitions + "\n");

                ByteArrayOutputStream bOut;
                byte[] cipherText = new byte[0];
                repetitions = 0;
                finishTime = System.currentTimeMillis() + rep_aes;
                while(System.currentTimeMillis() <= finishTime) {
                        long start = System.nanoTime();
                        ByteArrayInputStream bIn = new ByteArrayInputStream(input);
                        CipherInputStream cIn = new CipherInputStream(bIn, cipher);
                        bOut = new ByteArrayOutputStream();

                        int ch;
                        while ((ch = cIn.read()) >= 0) {
                                bOut.write(ch);
                        }

                        long end = System.nanoTime();
                        long microseconds = (end - start) / 1000;
                        writer.write("Time to encrypt: " + microseconds + " ms" + "\n");

                        cipherText = bOut.toByteArray();
                        repetitions +=1;
                }
                writer.write("Times performed encryption" + repetitions + "\n");
                repetitions = 0;
                finishTime = System.currentTimeMillis() + rep_aes;
                while(System.currentTimeMillis() <= finishTime) {
                        // decryption pass

                        long start = System.nanoTime();
                        bOut = new ByteArrayOutputStream();
                        CipherOutputStream cOut = new CipherOutputStream(bOut, cipher);
                        cOut.write(cipherText);
                        cOut.close();
                        long end = System.nanoTime();
                        long microseconds = (end - start) / 1000;
                        writer.write("Time to decrypt: " + microseconds + " ms" + "\n");

                        repetitions +=1;
                }
                writer.write("Times performed decrpytion" + repetitions + "\n");


        }


}



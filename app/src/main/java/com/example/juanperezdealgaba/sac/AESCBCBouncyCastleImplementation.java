package com.example.juanperezdealgaba.sac;


import android.widget.TextView;

import java.io.FileWriter;
import java.io.IOException;
import java.io.Writer;
import java.security.SecureRandom;

import java.io.UnsupportedEncodingException;

import org.spongycastle.crypto.DataLengthException;
import org.spongycastle.crypto.InvalidCipherTextException;
import org.spongycastle.util.encoders.Hex;


/**
 * Created by juanperezdealgaba on 26/2/18.
 *  In this class we implement the AESBouncyCastle function. The input will be
 * randomly generated by RandomStringGenerator(), then to byte[] converted and at the
 * end encrypted. The shown time is only the time of the encrypt() function.
 *
 * Then the process will be done backwards.
 */

    public class AESCBCBouncyCastleImplementation {

    /**
     *
     * @param input
     * @param writer
     * @throws DataLengthException
     * @throws InvalidCipherTextException
     * @throws IOException
     *
     * This class also uses a FileWriter to create the Report that will be se send and also modifies
     * the textView to show the results to the user.
     */

        public void AESCBC(String input, FileWriter writer, TextView results) throws DataLengthException,
        InvalidCipherTextException, IOException{

            SecureRandom random = new SecureRandom();
            byte[] key = new byte[32];
            random.nextBytes(key);



            AESCBCBouncyCastle cabc = new AESCBCBouncyCastle();
            cabc.setKey(key);


            System.out.println("Input[" + input.length() + "]: " + input);

            byte[] plain = input.getBytes("UTF-8");
            System.out.println("Plaintext[" + plain.length + "]: " + new String(Hex.encode(plain)));

            long startTimeEncrypt = System.nanoTime();
            byte[] encr = cabc.encrypt(plain);
            long endTimeEncrypt = System.nanoTime();
            long durationEncrypt = (endTimeEncrypt - startTimeEncrypt);

            System.out.println("Encrypted[" + encr.length + "]: " + new String(Hex.encode(encr)));
            System.out.println("Time to encrypt:" + durationEncrypt + "ms");

            results.append("Time to encrypt:" + durationEncrypt + "ms\n");

            writer.write("Time to encrypt:" + durationEncrypt + "ms\n");

            long startTimeDecrypt = System.nanoTime();
            byte[] decr = cabc.decrypt(encr);
            long endTimeDecrypt = System.nanoTime();
            long durationDecrypt = (endTimeDecrypt - startTimeDecrypt);

            writer.write("Time to decrypt:" + durationDecrypt + "ms\n");
            results.append("Time to decrypt:" + durationDecrypt + "ms\n");

            System.out.println("Decrypted[" + decr.length + "]: " + new String(Hex.encode(decr)));
            System.out.println("Time to decrypt:" + durationDecrypt + "ms");

            String output = new String(decr, "UTF-8");
            System.out.println("Output[" + output.length() + "]: " + output);



        }

    /**
     *
     * @param input
     * @throws UnsupportedEncodingException
     * @throws DataLengthException
     * @throws InvalidCipherTextException
     *
     * This class doesn´t use a writer to ease quick tests.
     */
    public void AESCBC(String input) throws UnsupportedEncodingException, DataLengthException,
            InvalidCipherTextException{

        SecureRandom random = new SecureRandom();
        byte[] key = new byte[32];
        random.nextBytes(key);


        AESCBCBouncyCastle cabc = new AESCBCBouncyCastle();
        cabc.setKey(key);

        System.out.println("************AES/CBC*************");
        System.out.println("Input[" + input.length() + "]: " + input);

        byte[] plain = input.getBytes("UTF-8");
        System.out.println("Plaintext[" + plain.length + "]: " + new String(Hex.encode(plain)));

        long startTimeEncrypt = System.nanoTime();
        byte[] encr = cabc.encrypt(plain);
        long endTimeEncrypt = System.nanoTime();
        long durationEncrypt = (endTimeEncrypt - startTimeEncrypt);

        System.out.println("Encrypted[" + encr.length + "]: " + new String(Hex.encode(encr)));
        System.out.println("Time to encrypt:" + durationEncrypt + "ms");

        long startTimeDecrypt = System.nanoTime();
        byte[] decr = cabc.decrypt(encr);
        long endTimeDecrypt = System.nanoTime();
        long durationDecrypt = (endTimeDecrypt - startTimeDecrypt);

        System.out.println("Decrypted[" + decr.length + "]: " + new String(Hex.encode(decr)));
        System.out.println("Time to decrypt:" + durationDecrypt + "ms");

        String output = new String(decr, "UTF-8");
        System.out.println("Output[" + output.length() + "]: " + output);

        System.out.println("**********************************");

    }

    public void AESCBC(FileWriter writer, TextView results, int repetitions) throws UnsupportedEncodingException, DataLengthException,
            InvalidCipherTextException,IOException{

        System.out.println("************Bouncy Castle/AES/CBC**************");
        results.append("\n************Bouncy Castle/AES/CBC***************\n");
        writer.write("\n************Bouncy Castle/AES/CBC***************\n");

        for(int i =0; i < repetitions; i++) {
            RandomStringGenerator string = new RandomStringGenerator();
            String input = string.generateRandomString();
            SecureRandom random = new SecureRandom();
            byte[] key = new byte[32];
            random.nextBytes(key);


            AESCBCBouncyCastle cabc = new AESCBCBouncyCastle();
            cabc.setKey(key);


            System.out.println("Input[" + input.length() + "]: " + input);

            byte[] plain = input.getBytes("UTF-8");
            System.out.println("Plaintext[" + plain.length + "]: " + new String(Hex.encode(plain)));

            long startTimeEncrypt = System.nanoTime();
            byte[] encr = cabc.encrypt(plain);
            long endTimeEncrypt = System.nanoTime();
            long durationEncrypt = (endTimeEncrypt - startTimeEncrypt);

            System.out.println("Encrypted[" + encr.length + "]: " + new String(Hex.encode(encr)));
            System.out.println("Time to encrypt:" + durationEncrypt + "ms");

            results.append("Time to encrypt:" + durationEncrypt + "ms\n");

            writer.write("Time to encrypt:" + durationEncrypt + "ms\n");

            long startTimeDecrypt = System.nanoTime();
            byte[] decr = cabc.decrypt(encr);
            long endTimeDecrypt = System.nanoTime();
            long durationDecrypt = (endTimeDecrypt - startTimeDecrypt);

            writer.write("Time to decrypt:" + durationDecrypt + "ms\n");
            results.append("Time to decrypt:" + durationDecrypt + "ms\n");

            System.out.println("Decrypted[" + decr.length + "]: " + new String(Hex.encode(decr)));
            System.out.println("Time to decrypt:" + durationDecrypt + "ms");

            String output = new String(decr, "UTF-8");
            System.out.println("Output[" + output.length() + "]: " + output);
        }

        System.out.println("***********************\n");
        writer.write("********************************\n");
        results.append("**********************************\n");

    }

    }

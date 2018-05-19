package com.example.juanperezdealgaba.sac;

import android.os.AsyncTask;
import android.util.Log;
import android.widget.TextView;

import org.spongycastle.crypto.AsymmetricCipherKeyPair;

import java.io.FileWriter;


import static com.example.juanperezdealgaba.sac.RSA.Decrypt;
import static com.example.juanperezdealgaba.sac.RSA.Encrypt;
import static com.example.juanperezdealgaba.sac.RSA.GenerateKeys;

/**
 * This class test the encryption and decryption time of RSA. First, the keypair is generated, then
 * it is encrypted and this time messed. The process will be done nackwards after.
 *
 */

public class RSAImplementation {

    /**
     *
     * @param randomString
     * @param writer
     * @param results
     * @throws Exception
     */
    public void RSA(String randomString, FileWriter writer, TextView results) throws
             Exception{

        try {
            System.out.println("************RSA**************");
            results.append("\n************RSA***************\n");
            writer.write("\n************RSA***************\n");

            for(int i = 0;i < 5; i++) {
                System.out.println("Plaintext[" + randomString.length() + "]: " + randomString);
                AsymmetricCipherKeyPair keyPair = GenerateKeys();
                String plainMessage = randomString;
                long startTimeEncrypt = System.nanoTime();
                String encryptedMessage = Encrypt(plainMessage.getBytes("UTF-8"),
                        keyPair.getPublic());
                long endTimeEncrypt = System.nanoTime();
                long durationEncrypt = (endTimeEncrypt - startTimeEncrypt);
                System.out.println("Encrypted[" + encryptedMessage.length() + "]: " + encryptedMessage);
                System.out.println("Time to encrypt:" + durationEncrypt + "ms\n");
                writer.write("Time to encrypt:" + durationEncrypt + "ms\n");
                results.append("Time to encrypt:" + durationEncrypt + "ms\n");

                long startTimeDecrypt = System.nanoTime();
                String decryptedMessage = Decrypt(encryptedMessage, keyPair.getPrivate());
                long endTimeDecrypt = System.nanoTime();
                long durationDecrypt = (endTimeDecrypt - startTimeDecrypt);
                writer.write("Time to decrypt:" + durationDecrypt + "ms\n");
                results.append("Time to decrypt:" + durationDecrypt + "ms\n");
                System.out.println("Decrypted[" + decryptedMessage.length() + "]: " + decryptedMessage);
                System.out.println("Time to decrypt:" + durationDecrypt + "ms");
            }
            System.out.println("********************************");
            writer.write("********************************\n");
            results.append("********************************\n");
        }catch(Exception i){
            throw new RuntimeException(i);
        }
    }

    public void RSA(String randomString) throws Exception{
        System.out.println("************RSA**************");

        System.out.println("Plaintext[" + randomString.length() + "]: " + randomString);
        AsymmetricCipherKeyPair keyPair = GenerateKeys();
        String plainMessage = randomString;
        long startTimeEncrypt = System.nanoTime();
        String encryptedMessage = Encrypt(plainMessage.getBytes("UTF-8"),
                keyPair.getPublic());
        long endTimeEncrypt = System.nanoTime();
        long durationEncrypt = (endTimeEncrypt - startTimeEncrypt);
        System.out.println("Encrypted[" + encryptedMessage.length() + "]: " + randomString);
        System.out.println("Time to encrypt:" + durationEncrypt+ "ms\n");


        long startTimeDecrypt = System.nanoTime();
        String decryptedMessage = Decrypt(encryptedMessage, keyPair.getPrivate());
        long endTimeDecrypt = System.nanoTime();
        long durationDecrypt = (endTimeDecrypt - startTimeDecrypt);

        System.out.println("Decrypted[" + decryptedMessage.length() + "]: " + decryptedMessage);
        System.out.println("Time to decrypt:" + durationDecrypt + "ms");
        System.out.println("Plain text was: " + plainMessage + " and decrypted text is: " +
                decryptedMessage);
        System.out.println("********************************");


    }
}

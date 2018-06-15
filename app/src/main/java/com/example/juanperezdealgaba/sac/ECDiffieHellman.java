package com.example.juanperezdealgaba.sac;

import java.io.FileWriter;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;
import java.util.Date;
import java.sql.Timestamp;

import javax.crypto.KeyAgreement;

import org.spongycastle.jce.ECNamedCurveTable;
import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.jce.spec.ECParameterSpec;

public class ECDiffieHellman {


    public static void GetTimestamp(String info) {
        System.out.println(info + new Timestamp((new Date()).getTime()));
    }

    public static boolean GenerateAgreement() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeyException {
        ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256r1");

        KeyPairGenerator g = KeyPairGenerator.getInstance("ECDH", "SC");

        g.initialize(ecSpec, new SecureRandom());

        KeyPair aKeyPair = g.generateKeyPair();

        KeyAgreement aKeyAgree = KeyAgreement.getInstance("ECDH", "SC");

        aKeyAgree.init(aKeyPair.getPrivate());

        KeyPair bKeyPair = g.generateKeyPair();

        KeyAgreement bKeyAgree = KeyAgreement.getInstance("ECDH", "SC");

        bKeyAgree.init(bKeyPair.getPrivate());

        //
        // agreement
        //
        aKeyAgree.doPhase(bKeyPair.getPublic(), true);
        bKeyAgree.doPhase(aKeyPair.getPublic(), true);

        byte[] aSecret = aKeyAgree.generateSecret();
        byte[] bSecret = bKeyAgree.generateSecret();

//        System.out.println(Arrays.toString(aSecret));
//        System.out.println(Arrays.toString(bSecret));

        return MessageDigest.isEqual(aSecret, bSecret);
    }

    public void GenerateAgreementTime(FileWriter writer, long rep_key, long rep_agree) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeyException {
        byte[] aSecret;
        byte[] bSecret;

        try {


            int repetitions = 0;
            long finishTime = System.currentTimeMillis() + rep_key;
            while (System.currentTimeMillis() <= finishTime) {
                long start = System.nanoTime();
                ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256r1");

                KeyPairGenerator g = KeyPairGenerator.getInstance("ECDH", "SC");

                g.initialize(ecSpec, new SecureRandom());

                KeyPair aKeyPair = g.generateKeyPair();

                KeyAgreement aKeyAgree = KeyAgreement.getInstance("ECDH", "SC");

                aKeyAgree.init(aKeyPair.getPrivate());

                KeyPair bKeyPair = g.generateKeyPair();

                KeyAgreement bKeyAgree = KeyAgreement.getInstance("ECDH", "SC");

                bKeyAgree.init(bKeyPair.getPrivate());

                long end = System.nanoTime();
                long microseconds = (end - start) / 1000;

                writer.write("Time to set key: " + microseconds + " ms\n");
                repetitions += 1;
            }
            writer.write("Times set key: " + repetitions + "\n");


        //
        // agreement
        //

        ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256r1");

        KeyPairGenerator g = KeyPairGenerator.getInstance("ECDH", "SC");

        g.initialize(ecSpec, new SecureRandom());

        KeyPair aKeyPair = g.generateKeyPair();

        KeyAgreement aKeyAgree = KeyAgreement.getInstance("ECDH", "SC");

        aKeyAgree.init(aKeyPair.getPrivate());

        KeyPair bKeyPair = g.generateKeyPair();

        KeyAgreement bKeyAgree = KeyAgreement.getInstance("ECDH", "SC");

        bKeyAgree.init(bKeyPair.getPrivate());


        aKeyAgree.doPhase(bKeyPair.getPublic(), true);
        bKeyAgree.doPhase(aKeyPair.getPublic(), true);


        repetitions = 0;
        finishTime = System.currentTimeMillis() + rep_agree;
        while (System.currentTimeMillis() <= finishTime) {
            long start = System.nanoTime();
            aSecret = aKeyAgree.generateSecret();
            long end = System.nanoTime();
            long microseconds = (end - start) / 1000;
            bSecret = bKeyAgree.generateSecret();

//        System.out.println(Arrays.toString(aSecret));
//        System.out.println(Arrays.toString(bSecret));

            System.out.println(MessageDigest.isEqual(aSecret, bSecret));
            writer.write("Time to generate key agreement: " + microseconds + " ms" + "\n");
            //System.out.println("plain : " + new String(bOut.toByteArray()));

            repetitions +=1;
        }
            writer.write("Times performed" + repetitions);
        } catch (IOException i) {
            throw new RuntimeException(i);
        }
    }
}
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

    public void GenerateAgreementTime(FileWriter writer, long rep_key, long rep_agree,int rep_total) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeyException {
        byte[] aSecret;
        byte[] bSecret;



            int repetitions = 0;
            long finishTime = System.currentTimeMillis() + rep_key;
            long start = System.nanoTime();
            while (System.currentTimeMillis() <= finishTime) {
                ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256r1");

                KeyPairGenerator g = KeyPairGenerator.getInstance("ECDH", "SC");

                g.initialize(ecSpec, new SecureRandom());

                KeyPair aKeyPair = g.generateKeyPair();

                KeyAgreement aKeyAgree = KeyAgreement.getInstance("ECDH", "SC");

                aKeyAgree.init(aKeyPair.getPrivate());

                KeyPair bKeyPair = g.generateKeyPair();

                KeyAgreement bKeyAgree = KeyAgreement.getInstance("ECDH", "SC");

                bKeyAgree.init(bKeyPair.getPrivate());

                repetitions += 1;
            }
            long end = System.nanoTime();
            long elapsedTime = end - start;
            double seconds = (double) elapsedTime / 1000000000.0;
            try {
                writer.write("Time setting key: " + (repetitions / seconds) + " times/second" + "\n");
                writer.write("Repetitions setting key: " + repetitions + "\n");
                writer.write("Seconds:" + seconds + "\n" );

            } catch (IOException e) {
                e.printStackTrace();
            }

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

            bool_value.value = true;

            for (int i = 0; i < rep_total; i++){
                repetitions = 0;
            start = System.nanoTime();
            while (bool_value.value) {

                aSecret = aKeyAgree.generateSecret();


                //bSecret = bKeyAgree.generateSecret();

//        System.out.println(Arrays.toString(aSecret));
//        System.out.println(Arrays.toString(bSecret));

                //System.out.println(MessageDigest.isEqual(aSecret, bSecret));
                repetitions += 1;
            }
            end = System.nanoTime();
             elapsedTime = end - start;
             seconds = (double) elapsedTime / 1000000000.0;
            try {
                bool_value.value = true;
                writer.write("Repetitions: " + repetitions + "\n");
                writer.write("Seconds: " + seconds + "\n");
                writer.write("Key Agreements: " + repetitions / seconds + " key agreement/second" + "\n");

            } catch (IOException e) {
                e.printStackTrace();
            }
            }
        }
    }

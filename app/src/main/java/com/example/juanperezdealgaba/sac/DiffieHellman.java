package com.example.juanperezdealgaba.sac;

import android.widget.TextView;

import org.spongycastle.jce.provider.BouncyCastleProvider;

import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.KeyAgreement;
import javax.crypto.spec.DHParameterSpec;

public class DiffieHellman {



    public  void testDH(FileWriter writer, TextView results,int rep_agree) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException,InvalidParameterSpecException,InvalidKeyException{


            Security.addProvider(new BouncyCastleProvider());
            AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator.getInstance("DH");
            paramGen.init(2048); // number of bits


        Keys key_st = new Keys();
        BigInteger p512 = key_st.returnP();
        BigInteger g512 = key_st.returnG();


//A
            KeyPairGenerator akpg = KeyPairGenerator.getInstance("DiffieHellman");

            DHParameterSpec param = new DHParameterSpec(p512, g512);

            akpg.initialize(param);
            KeyPair kp = akpg.generateKeyPair();

//B
            KeyPairGenerator bkpg = KeyPairGenerator.getInstance("DiffieHellman");

            DHParameterSpec param2 = new DHParameterSpec(p512, g512);

            bkpg.initialize(param2);
            KeyPair kp2 = bkpg.generateKeyPair();


            KeyAgreement aKeyAgree = KeyAgreement.getInstance("DiffieHellman");
            KeyAgreement bKeyAgree = KeyAgreement.getInstance("DiffieHellman");

            aKeyAgree.init(kp.getPrivate());
            bKeyAgree.init(kp2.getPrivate());

            aKeyAgree.doPhase(kp2.getPublic(), true);
            bKeyAgree.doPhase(kp.getPublic(), true);
            int repetitions = 0;
            long start = System.nanoTime();
            for(int i = 0; i < rep_agree; i++) {

                byte[] ASharedSecret = aKeyAgree.generateSecret();
                //long end = System.nanoTime();
                //long result = (end - start) / 1000;
                //byte[] BSharedSecret = bKeyAgree.generateSecret();
                repetitions += 1;
            }
            long end = System.nanoTime();
            long elapsedTime = end - start;
            double seconds = (double) elapsedTime / 1000000000.0;
            try {
                writer.write("Seconds:" + seconds + "\n" );
                writer.write("Time setting key: " + (repetitions / seconds) + " times/second" + "\n");
                writer.write("Repetitions setting key: " + repetitions + "\n");
            } catch (IOException e) {
                e.printStackTrace();
            }


    }

    public  void testDHTime(FileWriter writer, TextView results,long rep_key,long rep_agree,int rep_total) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException,InvalidParameterSpecException,InvalidKeyException{


            Security.addProvider(new BouncyCastleProvider());
            AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator.getInstance("DH");
            paramGen.init(2048); // number of bits


        Keys key_st = new Keys();
        BigInteger p512 = key_st.returnP();
        BigInteger g512 = key_st.returnG();


//A
            int repetitions = 0;
            long start = System.nanoTime();
            long finishTime = System.currentTimeMillis() + rep_key;
            while (System.currentTimeMillis() <= finishTime) {

                KeyPairGenerator akpg = KeyPairGenerator.getInstance("DiffieHellman");

                DHParameterSpec param = new DHParameterSpec(p512, g512);

                akpg.initialize(param);
                KeyPair kp = akpg.generateKeyPair();

//B
                KeyPairGenerator bkpg = KeyPairGenerator.getInstance("DiffieHellman");

                DHParameterSpec param2 = new DHParameterSpec(p512, g512);
                System.out.println("Prime: " + p512);
                System.out.println("Base: " + g512);
                bkpg.initialize(param2);
                KeyPair kp2 = bkpg.generateKeyPair();


                KeyAgreement aKeyAgree = KeyAgreement.getInstance("DiffieHellman");
                KeyAgreement bKeyAgree = KeyAgreement.getInstance("DiffieHellman");

                aKeyAgree.init(kp.getPrivate());
                bKeyAgree.init(kp2.getPrivate());

                aKeyAgree.doPhase(kp2.getPublic(), true);
                bKeyAgree.doPhase(kp.getPublic(), true);
                repetitions += 1;
            }
            long end = System.nanoTime();
            long elapsedTime = end - start;
            double seconds = (double) elapsedTime / 1000000000.0;
            try {
                writer.write("Time setting key: " + (repetitions / seconds) + " times/second" + "\n");
                writer.write("Repetitions setting key: " + repetitions + "\n");
            } catch (IOException e) {
                e.printStackTrace();
            }

            KeyPairGenerator akpg = KeyPairGenerator.getInstance("DiffieHellman");

            DHParameterSpec param = new DHParameterSpec(p512, g512);
            System.out.println("Prime: " + p512);
            System.out.println("Base: " + g512);
            akpg.initialize(param);
            KeyPair kp = akpg.generateKeyPair();

//B
            KeyPairGenerator bkpg = KeyPairGenerator.getInstance("DiffieHellman");

            DHParameterSpec param2 = new DHParameterSpec(p512, g512);
            System.out.println("Prime: " + p512);
            System.out.println("Base: " + g512);
            bkpg.initialize(param2);
            KeyPair kp2 = bkpg.generateKeyPair();


            KeyAgreement aKeyAgree = KeyAgreement.getInstance("DiffieHellman");
            KeyAgreement bKeyAgree = KeyAgreement.getInstance("DiffieHellman");

            aKeyAgree.init(kp.getPrivate());
            bKeyAgree.init(kp2.getPrivate());

            aKeyAgree.doPhase(kp2.getPublic(), true);
            bKeyAgree.doPhase(kp.getPublic(), true);

            bool_value.value = true;

            for (int i = 0; i < rep_total; i++){
                repetitions = 0;
            finishTime = System.currentTimeMillis() + rep_agree;
            start = System.nanoTime();
            while (bool_value.value) {
                byte[] ASharedSecret = aKeyAgree.generateSecret();
                    end = System.nanoTime();
                long result = (end - start) / 1000;
                //byte[] BSharedSecret = bKeyAgree.generateSecret();

                //System.out.println(MessageDigest.isEqual(ASharedSecret, BSharedSecret));

                repetitions += 1;
            }
            end = System.nanoTime();
            elapsedTime = end - start;
            seconds = (double) elapsedTime / 1000000000.0;
            try {
                bool_value.value = true;
                writer.write("Seconds:" + seconds + "\n" );
                writer.write("Repetitions: " + repetitions + "\n");
                writer.write("Key Agreements: " + repetitions / seconds + " key agreement/second" + "\n");

            } catch (IOException e) {
                e.printStackTrace();
            }
        }

    }
}

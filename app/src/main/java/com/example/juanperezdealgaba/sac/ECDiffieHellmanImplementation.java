package com.example.juanperezdealgaba.sac;

import android.widget.TextView;

import org.spongycastle.jce.ECNamedCurveTable;
import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.jce.spec.ECParameterSpec;

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

import javax.crypto.KeyAgreement;

import static com.example.juanperezdealgaba.sac.ECDiffieHellman.GenerateAgreement;
import static com.example.juanperezdealgaba.sac.ECDiffieHellman.GetTimestamp;

/**
 * Created by juanperezdealgaba on 2/3/18.
 */

public class ECDiffieHellmanImplementation {


    public void startDiffieHellman(FileWriter writer, TextView results, int rep_agree) throws NoSuchAlgorithmException, NoSuchProviderException,
            InvalidAlgorithmParameterException,InvalidKeyException, IOException{
        Security.addProvider(new BouncyCastleProvider());


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

    for(int i = 0; i < rep_agree; i++) {
        long start = System.nanoTime();

        byte[] aSecret = aKeyAgree.generateSecret();

        long end = System.nanoTime();
        long result = (end - start) / 1000;
        writer.write("Time to generate key agreement :" + result + " ms\n");
        byte[] bSecret = bKeyAgree.generateSecret();

        System.out.println(MessageDigest.isEqual(aSecret, bSecret));
    }

        //results.append("Time to generate key agreement :" + timeKeyAgreement+ "\n");


    }

    public void startDiffieHellman(FileWriter writer, TextView results, long result_time) throws NoSuchAlgorithmException, NoSuchProviderException,
            InvalidAlgorithmParameterException,InvalidKeyException, IOException{
        Security.addProvider(new BouncyCastleProvider());
        System.out.println("***********Bouncy Castle-ECDH**************");
        writer.write("\n**********Bouncy Castle-ECDH********\n");
        results.append("*******Bouncy Castle-ECDH******\n");
        int algo_repet = 0;
        while (System.currentTimeMillis() < result_time) {
            long startKeyAgreement = System.nanoTime();
            System.out.println(GenerateAgreement());
            long endKeyAgreement = System.nanoTime();
            long timeKeyAgreement = (endKeyAgreement - startKeyAgreement);
            writer.write("Time to generate key agreement :" + timeKeyAgreement + "\n");
            results.append("Time to generate key agreement :" + timeKeyAgreement + "\n");
            algo_repet += 1;
        }

        System.out.println("Times executed:" + algo_repet + "\n");
        writer.write("Times executed:" + algo_repet + "\n");
        results.append("Times executed:" + algo_repet + "\n");

        System.out.println("***********************\n");
        writer.write("********************************\n");
        results.append("**********************************\n");

    }

    public void startDiffieHellmanTime(FileWriter writer, TextView results, long rep_key,long result_time) throws NoSuchAlgorithmException, NoSuchProviderException,
            InvalidAlgorithmParameterException,InvalidKeyException, IOException{
        Security.addProvider(new BouncyCastleProvider());
        System.out.println("***********Bouncy Castle-ECDH**************");
        writer.write("\n**********Bouncy Castle-ECDH********\n");

            ECDiffieHellman test = new ECDiffieHellman();
            test.GenerateAgreementTime(writer,rep_key,result_time);



        System.out.println("***********************\n");
        writer.write("********************************\n");

    }





    public void startDiffieHellman() throws NoSuchAlgorithmException, NoSuchProviderException,
            InvalidAlgorithmParameterException,InvalidKeyException{
        Security.addProvider(new BouncyCastleProvider());

        GetTimestamp("Key Generation started: ");
        System.out.println(GenerateAgreement());
//		System.out.println(keys.getPublic().toString());
//		System.out.println(keys.getPrivate().toString());
        GetTimestamp("Key Generation ended: ");
    }
}

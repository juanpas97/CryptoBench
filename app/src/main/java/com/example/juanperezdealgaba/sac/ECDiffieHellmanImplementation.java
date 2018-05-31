package com.example.juanperezdealgaba.sac;

import android.widget.TextView;

import org.spongycastle.jce.provider.BouncyCastleProvider;

import java.io.FileWriter;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;

import static com.example.juanperezdealgaba.sac.ECDiffieHellman.GenerateAgreement;
import static com.example.juanperezdealgaba.sac.ECDiffieHellman.GetTimestamp;

/**
 * Created by juanperezdealgaba on 2/3/18.
 */

public class ECDiffieHellmanImplementation {


    public void startDiffieHellman(FileWriter writer, TextView results) throws NoSuchAlgorithmException, NoSuchProviderException,
            InvalidAlgorithmParameterException,InvalidKeyException, IOException{
        Security.addProvider(new BouncyCastleProvider());


        long startKeyAgreement = System.nanoTime();
        System.out.println(GenerateAgreement());
        long endKeyAgreement = System.nanoTime();
        long timeKeyAgreement = (endKeyAgreement - startKeyAgreement);
        writer.write("Time to generate key agreement :" + timeKeyAgreement+ "\n");
        results.append("Time to generate key agreement :" + timeKeyAgreement+ "\n");


    }

    public void startDiffieHellman(FileWriter writer, TextView results, long result_time) throws NoSuchAlgorithmException, NoSuchProviderException,
            InvalidAlgorithmParameterException,InvalidKeyException, IOException{
        Security.addProvider(new BouncyCastleProvider());
        System.out.println("***********Bouncy Castle/DH/ Key Agreement**************");
        writer.write("\n**********Bouncy Castle/DH/ Key Agreement********\n");
        results.append("*******Bouncy Castle/DH/ Key Agreement******\n");
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
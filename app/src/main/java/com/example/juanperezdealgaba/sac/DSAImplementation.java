package com.example.juanperezdealgaba.sac;

import android.widget.TextView;

import java.io.FileWriter;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;

import static com.example.juanperezdealgaba.sac.DSA.GenerateKeys;
import static com.example.juanperezdealgaba.sac.DSA.GenerateSignature;
import static com.example.juanperezdealgaba.sac.DSA.ValidateSignature;
import static com.example.juanperezdealgaba.sac.ECDiffieHellman.GetTimestamp;

/**
 * Created by juanperezdealgaba on 2/3/18.
 */

public class DSAImplementation {

    public void testDSA(String input, FileWriter writer, TextView results) throws NoSuchAlgorithmException, NoSuchProviderException,SignatureException,
            InvalidAlgorithmParameterException, InvalidKeyException,
            IOException{

        System.out.println("***********DSA**************");
        writer.write("**********DSA***************\n");
        results.append("**********DSA************\n");
        String plaintext = input;
        GetTimestamp("Key Generation started: ");
        KeyPair keys = GenerateKeys();
        GetTimestamp("Key Generation ended: ");

        long startTimeGenSign = System.nanoTime();
        byte[] signature = GenerateSignature(plaintext, keys);
        long endTimeGenSign = System.nanoTime();
        long durationGenSign = (endTimeGenSign - startTimeGenSign);
        System.out.println("Time to generate Sign: " + durationGenSign + "ms\n");
        writer.write("Time to generate signature:" + durationGenSign + "ms\n");
        results.append("Time to generate signature:" + durationGenSign + "ms\n");


        long startValidateSign = System.nanoTime();
        boolean isValidated = ValidateSignature(plaintext, keys, signature);
        long endValidateSign = System.nanoTime();
        long durationValidateSign = (endValidateSign - startValidateSign);
        System.out.println("Result: " + isValidated);
        System.out.println("Time to validate Sign: " + durationValidateSign + "ms\n");
        writer.write("Time to validate signature:" + durationValidateSign + "ms\n");
        results.append("Time to validate signature:" + durationValidateSign + "ms\n");

        System.out.println("********************************");
        writer.write("********************************\n");
        results.append("********************************\n");

    }

    public void testDSA(String input) throws NoSuchAlgorithmException, NoSuchProviderException,SignatureException,
            InvalidAlgorithmParameterException,InvalidKeyException,
            IOException{

        System.out.println("***********DSA**************");
        String plaintext = input;
        GetTimestamp("Key Generation started: ");
        KeyPair keys = GenerateKeys();
//		System.out.println(keys.getPublic().toString());
//		System.out.println(keys.getPrivate().toString());
        GetTimestamp("Key Generation ended: ");

        long startTimeGenSign = System.nanoTime();
        byte[] signature = GenerateSignature(plaintext, keys);
        long endTimeGenSign = System.nanoTime();
        long durationGenSign = (endTimeGenSign - startTimeGenSign);
        System.out.println("Time to generate Sign: " + durationGenSign + "ms\n");



        long startValidateSign = System.nanoTime();
        boolean isValidated = ValidateSignature(plaintext, keys, signature);
        long endValidateSign = System.nanoTime();
        long durationValidateSign = (endValidateSign - startValidateSign);
        System.out.println("Result: " + isValidated);


        System.out.println("********************************");

    }
}

package com.example.juanperezdealgaba.sac;

import org.spongycastle.jce.provider.BouncyCastleProvider;

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


    public static void testDH() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException,InvalidParameterSpecException,InvalidKeyException{

        Security.addProvider(new BouncyCastleProvider());
        AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator.getInstance("DH");
        paramGen.init(2048); // number of bits

        byte[] g= {0x02};

        BigInteger p512 = new BigInteger("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
                "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
                "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
                "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
                "83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
                "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
                "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
                "DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
                "15728E5A8AACAA68FFFFFFFFFFFFFFFF",16);
        BigInteger g512 = new BigInteger(g);

//A
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


        byte[] ASharedSecret = aKeyAgree.generateSecret();
        byte[] BSharedSecret = bKeyAgree.generateSecret();

        System.out.println("Result:");
        System.out.println(MessageDigest.isEqual(ASharedSecret, BSharedSecret));

    }
}

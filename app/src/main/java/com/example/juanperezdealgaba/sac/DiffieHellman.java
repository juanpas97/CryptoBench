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


    public static void testDH() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException,InvalidParameterSpecException,InvalidKeyException{

        Security.addProvider(new BouncyCastleProvider());
        AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator.getInstance("DH");
        paramGen.init(2048); // number of bits


        BigInteger p512 = new BigInteger("AD107E1E9123A9D0D660FAA79559C51FA20D64E5683B9FD1" +
                "B54B1597B61D0A75E6FA141DF95A56DBAF9A3C407BA1DF15" +
                "EB3D688A309C180E1DE6B85A1274A0A66D3F8152AD6AC212" +
                "9037C9EDEFDA4DF8D91E8FEF55B7394B7AD5B7D0B6C12207" +
                "C9F98D11ED34DBF6C6BA0B2C8BBC27BE6A00E0A0B9C49708" +
                "B3BF8A317091883681286130BC8985DB1602E714415D9330" +
                "278273C7DE31EFDC7310F7121FD5A07415987D9ADC0A486D" +
                "CDF93ACC44328387315D75E198C641A480CD86A1B9E587E8" +
                "BE60E69CC928B2B9C52172E413042E9B23F10B0E16E79763" +
                "C9B53DCF4BA80A29E3FB73C16B8E75B97EF363E2FFA31F71" +
                "CF9DE5384E71B81C0AC4DFFE0C10E64F",16);
        BigInteger g512 = new BigInteger("AC4032EF4F2D9AE39DF30B5C8FFDAC506CDEBE7B89998CAF" +
                "74866A08CFE4FFE3A6824A4E10B9A6F0DD921F01A70C4AFA" +
                "AB739D7700C29F52C57DB17C620A8652BE5E9001A8D66AD7" +
                "C17669101999024AF4D027275AC1348BB8A762D0521BC98A" +
                "E247150422EA1ED409939D54DA7460CDB5F6C6B250717CBE" +
                "F180EB34118E98D119529A45D6F834566E3025E316A330EF" +
                "BB77A86F0C1AB15B051AE3D428C8F8ACB70A8137150B8EEB" +
                "10E183EDD19963DDD9E263E4770589EF6AA21E7F5F2FF381" +
                "B539CCE3409D13CD566AFBB48D6C019181E1BCFE94B30269" +
                "EDFE72FE9B6AA4BD7B5A0F1C71CFFF4C19C418E1F6EC0179" +
                "81BC087F2A7065B384B890D3191F2BFA",16);

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

    public  void testDH(FileWriter writer, TextView results,int rep_agree) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException,InvalidParameterSpecException,InvalidKeyException{


            Security.addProvider(new BouncyCastleProvider());
            AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator.getInstance("DH");
            paramGen.init(2048); // number of bits


            BigInteger p512 = new BigInteger("AD107E1E9123A9D0D660FAA79559C51FA20D64E5683B9FD1" +
                    "B54B1597B61D0A75E6FA141DF95A56DBAF9A3C407BA1DF15" +
                    "EB3D688A309C180E1DE6B85A1274A0A66D3F8152AD6AC212" +
                    "9037C9EDEFDA4DF8D91E8FEF55B7394B7AD5B7D0B6C12207" +
                    "C9F98D11ED34DBF6C6BA0B2C8BBC27BE6A00E0A0B9C49708" +
                    "B3BF8A317091883681286130BC8985DB1602E714415D9330" +
                    "278273C7DE31EFDC7310F7121FD5A07415987D9ADC0A486D" +
                    "CDF93ACC44328387315D75E198C641A480CD86A1B9E587E8" +
                    "BE60E69CC928B2B9C52172E413042E9B23F10B0E16E79763" +
                    "C9B53DCF4BA80A29E3FB73C16B8E75B97EF363E2FFA31F71" +
                    "CF9DE5384E71B81C0AC4DFFE0C10E64F", 16);
            BigInteger g512 = new BigInteger("AC4032EF4F2D9AE39DF30B5C8FFDAC506CDEBE7B89998CAF" +
                    "74866A08CFE4FFE3A6824A4E10B9A6F0DD921F01A70C4AFA" +
                    "AB739D7700C29F52C57DB17C620A8652BE5E9001A8D66AD7" +
                    "C17669101999024AF4D027275AC1348BB8A762D0521BC98A" +
                    "E247150422EA1ED409939D54DA7460CDB5F6C6B250717CBE" +
                    "F180EB34118E98D119529A45D6F834566E3025E316A330EF" +
                    "BB77A86F0C1AB15B051AE3D428C8F8ACB70A8137150B8EEB" +
                    "10E183EDD19963DDD9E263E4770589EF6AA21E7F5F2FF381" +
                    "B539CCE3409D13CD566AFBB48D6C019181E1BCFE94B30269" +
                    "EDFE72FE9B6AA4BD7B5A0F1C71CFFF4C19C418E1F6EC0179" +
                    "81BC087F2A7065B384B890D3191F2BFA", 16);

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


            BigInteger p512 = new BigInteger("AD107E1E9123A9D0D660FAA79559C51FA20D64E5683B9FD1" +
                    "B54B1597B61D0A75E6FA141DF95A56DBAF9A3C407BA1DF15" +
                    "EB3D688A309C180E1DE6B85A1274A0A66D3F8152AD6AC212" +
                    "9037C9EDEFDA4DF8D91E8FEF55B7394B7AD5B7D0B6C12207" +
                    "C9F98D11ED34DBF6C6BA0B2C8BBC27BE6A00E0A0B9C49708" +
                    "B3BF8A317091883681286130BC8985DB1602E714415D9330" +
                    "278273C7DE31EFDC7310F7121FD5A07415987D9ADC0A486D" +
                    "CDF93ACC44328387315D75E198C641A480CD86A1B9E587E8" +
                    "BE60E69CC928B2B9C52172E413042E9B23F10B0E16E79763" +
                    "C9B53DCF4BA80A29E3FB73C16B8E75B97EF363E2FFA31F71" +
                    "CF9DE5384E71B81C0AC4DFFE0C10E64F", 16);
            BigInteger g512 = new BigInteger("AC4032EF4F2D9AE39DF30B5C8FFDAC506CDEBE7B89998CAF" +
                    "74866A08CFE4FFE3A6824A4E10B9A6F0DD921F01A70C4AFA" +
                    "AB739D7700C29F52C57DB17C620A8652BE5E9001A8D66AD7" +
                    "C17669101999024AF4D027275AC1348BB8A762D0521BC98A" +
                    "E247150422EA1ED409939D54DA7460CDB5F6C6B250717CBE" +
                    "F180EB34118E98D119529A45D6F834566E3025E316A330EF" +
                    "BB77A86F0C1AB15B051AE3D428C8F8ACB70A8137150B8EEB" +
                    "10E183EDD19963DDD9E263E4770589EF6AA21E7F5F2FF381" +
                    "B539CCE3409D13CD566AFBB48D6C019181E1BCFE94B30269" +
                    "EDFE72FE9B6AA4BD7B5A0F1C71CFFF4C19C418E1F6EC0179" +
                    "81BC087F2A7065B384B890D3191F2BFA", 16);

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


            for (int i = 0; i < rep_total; i++){
                repetitions = 0;
            finishTime = System.currentTimeMillis() + rep_agree;
            start = System.nanoTime();
            while (System.currentTimeMillis() <= finishTime) {
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
                writer.write("Key Agreements: " + repetitions / seconds + " key agreement/second" + "\n");
                writer.write("Repetitions: " + repetitions + "\n");
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

    }
}

package com.example.juanperezdealgaba.sac;

import android.content.Context;

import android.os.Build;
import android.widget.TextView;


import org.spongycastle.crypto.InvalidCipherTextException;

import java.io.FileWriter;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;


/**
 * Created by juanperezdealgaba on 27/2/18.
 */

public class SuperTest {

    /**
     *
     * @param context
     * @return File
     *
     * The function returns a file which will be used after to send the E-mail
     */
        public Void startTest(String input,Context context, TextView results,FileWriter writer, int repetitions) {
            try {

                /**
                 * We create the file Report.txt in the previously created "EncryptApp"
                 * folder.
                 */

                /**
                 * We get the information of the mobile phone of the user and we write it
                 * in the file
                 */
                String myVersion = android.os.Build.VERSION.RELEASE;
                int sdkVersion = android.os.Build.VERSION.SDK_INT;
                String manufacturer = Build.MANUFACTURER;
                String device = Build.DEVICE;
                String model = Build.MODEL;

                String model_cpu = System.getProperty("os.arch");


                writer.write("Super Test Results\n");
                writer.write("-----------------------------------\n");
                writer.write("CPU Model: " + model_cpu + "\n");
                writer.write("Android Version: " + myVersion + "\n");
                writer.write("SDK Version: " + sdkVersion + "\n");
                writer.write("Manufacturer: " + manufacturer + "\n");
                writer.write("Device: " + device + "\n");
                writer.write("Model: " + model + "\n");
                results.setText("Super Test Results\n" + "*********************************\n"
                        + "Model CPU: " + model_cpu + "\n" + "Android Version:"+myVersion+"\n"+
                "SDK Version: "+ sdkVersion + "\n" + "Manufacturer: " + manufacturer + "\n" +
                        "Device: " + device + "\n" + "Model: " + model + "\n"
                + "********************************\n\n");
                writer.write("\n");
                writer.write("\n");
                writer.write("\n");

                System.out.println("***********Bouncy Castle**************");
                writer.write("**********Bouncy Castle***************\n");
                results.append("**********Bouncy Castle************\n");


                /**
                 * AES/CBC
                 */
                System.out.println("***********AES/CBC**************");
                writer.write("**********AES/CBC***************\n");
                results.append("**********AES/CBC************\n");

                for(int i = 0;i < repetitions; i++) {
                    AESCBCBouncyCastleImplementation test = new AESCBCBouncyCastleImplementation();
                    test.AESCBC(input, writer, results);
                    results.append("\n");
                }

                System.out.println("********************************");
                writer.write("********************************\n");
                results.append("********************************\n");

                /**
                 * AES/EBC
                 */

                //AESBouncyCastleImplementation testAES = new AESBouncyCastleImplementation();
                //testAES.AES(input, writer, results);
                //results.append("\n");


                /**
                 * Diffie Hellman
                 */
                System.out.println("***********DH/ Key Agreement**************");
                writer.write("\n**********DH/ Key Agreement********\n");
                results.append("*******DH/ Key Agreement******\n");

                for(int i = 0;i < repetitions; i++) {
                    DiffieHellmanImplementation testDH = new DiffieHellmanImplementation();
                    testDH.startDiffieHellman(writer, results);
                }

                System.out.println("***********************\n");
                writer.write("********************************\n");
                results.append("**********************************\n");

                /**
                 * DSA(Digital Signature Algorithm)
                 */

               // DSAImplementation testDSA = new DSAImplementation();
               // testDSA.testDSA(input,writer, results);


                /**
                 * MD5
                 */

                System.out.println("***********MD5**************");
                writer.write("**********MD5***************\n");
                results.append("**********MD5************\n");

                for(int i = 0;i < repetitions; i++) {
                    MD5Implementation testMD5 = new MD5Implementation();
                    testMD5.testmd5(input, writer, results);
                }

                System.out.println("********************************");
                writer.write("********************************\n");
                results.append("********************************\n");
                /**
                 * SHA3
                 */

               // SHA3Implementation testSHA3 = new SHA3Implementation();
               // testSHA3.testSHA3(input, writer, results);

                return null;

            } catch (NoSuchAlgorithmException e) {
                    throw new RuntimeException(e);
                } catch (InvalidCipherTextException i) {
                    throw new RuntimeException(i);
                } catch (UnsupportedEncodingException o) {
                    throw new RuntimeException(o);
                } catch (IOException j) {
                    throw new RuntimeException(j);
                } catch (Exception x){
                throw new RuntimeException(x);
            }

        }
}



package com.example.juanperezdealgaba.sac;

import android.annotation.SuppressLint;
import android.app.Activity;
import android.app.ListActivity;
import android.app.ProgressDialog;
import android.content.Context;
import android.os.AsyncTask;
import android.os.Build;
import android.util.Log;
import android.widget.TextView;

import com.snatik.storage.Storage;

import org.spongycastle.crypto.AsymmetricCipherKeyPair;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;





class CompleteTestParams {
    FileWriter writer;
    TextView results;
    int repetitions;
    Storage storage;

    CompleteTestParams(Storage storage, TextView results, int repetitions) {

        this.storage = storage;
        this.results = results;
        this.repetitions = repetitions;
    }
}


class CompleteTestAsync extends AsyncTask<CompleteTestParams, Void, TextView> {


    CompleteTestAsync(CompleteTestActivity a){
        this.activity = a;
        dialog = new ProgressDialog(activity);
    }

   public  CompleteTestActivity activity;
    public ProgressDialog dialog;

   @Override
    protected void onPreExecute() {
        super.onPreExecute();
        dialog = new ProgressDialog(activity);
        dialog.setMessage("Performing benchmarks");
        dialog.show();
    }



    @Override
    protected TextView doInBackground(CompleteTestParams... params) {
       Storage storage = params[0].storage;
        TextView results = params[0].results;
        int repetitions = params[0].repetitions;

        try {

            String path = storage.getExternalStorageDirectory();

            final String newDir = path + File.separator + "CryptoBench";

            final File report = new File(newDir, "Report.txt");
            report.mkdirs();

            if (report.exists())
                report.delete();

            final FileWriter writer = new FileWriter(report);


            String myVersion = android.os.Build.VERSION.RELEASE;
            int sdkVersion = android.os.Build.VERSION.SDK_INT;
            String manufacturer = Build.MANUFACTURER;
            String device = Build.DEVICE;
            String model = Build.MODEL;

            final String model_cpu = System.getProperty("os.arch");


            writer.write("Super Test Results\n");
            writer.write("-----------------------------------\n");
            writer.write("CPU Model: " + model_cpu + "\n");
            writer.write("Android Version: " + myVersion + "\n");
            writer.write("SDK Version: " + sdkVersion + "\n");
            writer.write("Manufacturer: " + manufacturer + "\n");
            writer.write("Device: " + device + "\n");
            writer.write("Model: " + model + "\n");


            writer.write("\n");
            writer.write("\n");
            writer.write("\n");
            String separate = "*********************************************" + "\n";
            String separate_lib = "*********************************************" + "\n"+ "\n"+ "\n"+ "\n";

            for (int i= 0; i< repetitions; i++){


                String BC = "***********Bouncy Castle**************" + "\n";
                System.out.println(BC);
                writer.write(BC);


                for (int blocksize = 128; blocksize <= 1024;){


                    System.out.println("Blocksize is:");
                    System.out.println(blocksize);
                    String block = "*************BLOCKSIZE: " + blocksize +"******************" + "\n";
                    writer.write(block);

                    String BCCBC= "***********AES/CBC**************" + "\n";
                    System.out.println(BCCBC);
                    writer.write(BCCBC);

                    AESCBC testCBC = new AESCBC();
                    testCBC.testCBC(writer,results,blocksize);

                    writer.write(separate);

                    String BCCTR= "***********AES/CTR**************" + "\n";
                    System.out.println(BCCTR);
                    writer.write(BCCTR);

                    AESCTR testCTR = new AESCTR();
                    testCTR.testCTR(writer, results, blocksize);

                    writer.write(separate);

                    String BCGCM= "***********AES/GCM**************" + "\n";
                    System.out.println(BCGCM);
                    writer.write(BCGCM);

                    AESGCM testGCM = new AESGCM();
                    testGCM.testGCM(writer, results, blocksize);

                    writer.write(separate);

                    String BCOFB= "***********AES/OFB**************" + "\n";
                    System.out.println(BCOFB);
                    writer.write(BCOFB);

                    AESOFB testOFB = new AESOFB();
                    testOFB.testOFB(writer, results, blocksize);

                    writer.write(separate);



                    String BCMD5= "***********MD-5**************" + "\n";
                    System.out.println(BCMD5);
                    writer.write(BCMD5);

                    MD5Implementation testmd5 = new MD5Implementation();
                    testmd5.testmd5(writer, results,blocksize);

                    writer.write(separate);

                    blocksize = blocksize*2;


                }

                String BCRSA= "***********RSA**************" + "\n";
                System.out.println(BCRSA);
                writer.write(BCRSA);


                RSAPrueba testRSABC = new RSAPrueba();
                testRSABC.testRSA(writer, results,128);

                writer.write(separate);

                String BCDH= "***********DH**************" + "\n";
                System.out.println(BCDH);
                writer.write(BCDH);

                DiffieHellman testDH = new DiffieHellman();
                testDH.testDH(writer, results);

                writer.write(separate);

                String BCECDH= "***********ECDH**************" + "\n";
                System.out.println(BCECDH);
                writer.write(BCECDH);

                ECDiffieHellmanImplementation testECDH = new ECDiffieHellmanImplementation();
                testECDH.startDiffieHellman(writer, results);

                writer.write(separate_lib);

                String mbed = "***********mbedTLS**************" + "\n";
                System.out.println(mbed);
                writer.write(mbed);

                for (int blocksize = 128; blocksize <= 1024;) {
                    String block = "*************BLOCKSIZE: " + blocksize +"******************" + "\n";
                    writer.write(block);
                    String mbedCBC= "***********AES/CBC**************" + "\n";
                    System.out.println(mbedCBC);
                    writer.write(mbedCBC);

                    mbedTLS test = new mbedTLS();
                    int[] timesAES = test.AESCBC(blocksize);

                    System.out.println("Time to encrypt:" + timesAES[0] + "ms\n");
                    writer.write("Time to encrypt:" + timesAES[0] + "ms\n");


                    System.out.println("Time to decrypt:" + timesAES[1] + "ms\n");
                    writer.write("Time to decrypt:" + timesAES[1] + "ms\n");

                    writer.write(separate);

                    String mbedCTR= "***********AES/CTR**************" + "\n";
                    System.out.println(mbedCTR);
                    writer.write(mbedCTR);

                    mbedTLS testCTR = new mbedTLS();
                    int[] timesAESCTR = testCTR.AESCTR(blocksize);

                    System.out.println("Time to encrypt:" + timesAESCTR[0] + "ms\n");
                    writer.write("Time to encrypt:" + timesAESCTR[0] + "ms\n");


                    System.out.println("Time to decrypt:" + timesAESCTR[1] + "ms\n");
                    writer.write("Time to decrypt:" + timesAESCTR[1] + "ms\n");

                    writer.write(separate);

                    String mbedGCM= "***********AES/GCM**************" + "\n";
                    System.out.println(mbedGCM);
                    writer.write(mbedGCM);

                    mbedTLS testGCM = new mbedTLS();
                    int[] timesAESGCM = testGCM.AESGCM(blocksize);

                    System.out.println("Time to encrypt:" + timesAESGCM[0] + "ms\n");
                    writer.write("Time to encrypt:" + timesAESGCM[0] + "ms\n");


                    System.out.println("Time to decrypt:" + timesAESGCM[1] + "ms\n");
                    writer.write("Time to decrypt:" + timesAESGCM[1] + "ms\n");

                    writer.write(separate);

                    String mbedmd5= "***********MD5**************" + "\n";
                    System.out.println(mbedmd5);
                    writer.write(mbedmd5);

                    mbedTLS testmd5 = new mbedTLS();
                    int[] timesmd5 = testmd5.MD5(blocksize);

                    System.out.println("Time to generate hash:" + timesmd5[1] + "ms\n");
                    writer.write("Time to generate hash: " + timesmd5[1] + "ms\n");

                    writer.write(separate);

                    blocksize = blocksize*2;

                }

                String mbedRSA= "***********RSA**************" + "\n";
                System.out.println(mbedRSA);
                writer.write(mbedRSA);

                mbedTLS testRSAmbed = new mbedTLS();
                int[] timesRSA = testRSAmbed.RSA(128);

                System.out.println("Time to encrypt:" + timesRSA[0] + "ms\n");
                writer.write("Time to encrypt:" + timesRSA[0] + "ms\n");


                System.out.println("Time to decrypt:" + timesRSA[1] + "ms\n");
                writer.write("Time to decrypt:" + timesRSA[1] + "ms\n");

                writer.write(separate);

                String mbeddh= "***********DH**************" + "\n";
                System.out.println(mbeddh);
                writer.write(mbeddh);

                mbedTLS testDHmbed = new mbedTLS();
                int[] timesDH = testDHmbed.DH();

                System.out.println("Time to key agreement:" + timesDH[1] + "ms\n");
                writer.write("Time to key agreement" + timesDH[1] + "ms\n");

                writer.write(separate);

                String mbedecdh= "***********ECDH**************" + "\n";
                System.out.println(mbedecdh);
                writer.write(mbedecdh);

                mbedTLS testECDHmbed = new mbedTLS();
                int[] timesECDH = testECDHmbed.ECDH();

                System.out.println("Time to key agreement:" + timesECDH[1] + "ms\n");
                writer.write("Time to key agreement" + timesECDH[1] + "ms\n");

                writer.write(separate_lib);

                String wc = "***********WolfCrypt**************" + "\n";
                System.out.println(wc);
                writer.write(wc);

                for (int blocksize = 128; blocksize <= 1024;){

                    String block = "*************BLOCKSIZE: " + blocksize +"******************" + "\n";
                    writer.write(block);


                    String wcCBC= "***********AES/CBC**************" + "\n";
                    System.out.println(wcCBC);
                    writer.write(wcCBC);

                    WolfCrypt test = new WolfCrypt();
                    int[] timesAES = test.AESCBC(blocksize);

                    System.out.println("Time to encrypt:" + timesAES[0] + "ms\n");
                    writer.write("Time to encrypt:" + timesAES[0] + "ms\n");


                    System.out.println("Time to decrypt:" + timesAES[1] + "ms\n");
                    writer.write("Time to decrypt:" + timesAES[1] + "ms\n");


                    writer.write(separate);


                    String mbedCTR= "***********AES/CTR**************" + "\n";
                    System.out.println(mbedCTR);
                    writer.write(mbedCTR);

                    WolfCrypt testCTR = new WolfCrypt();
                    int[] timesAESCTR = testCTR.AESCTR(blocksize);

                    System.out.println("Time to encrypt:" + timesAESCTR[0] + "ms\n");
                    writer.write("Time to encrypt:" + timesAESCTR[0] + "ms\n");


                    System.out.println("Time to decrypt:" + timesAESCTR[1] + "ms\n");
                    writer.write("Time to decrypt:" + timesAESCTR[1] + "ms\n");

                    writer.write(separate);

                    String mbedGCM= "***********AES/GCM**************" + "\n";
                    System.out.println(mbedGCM);
                    writer.write(mbedGCM);

                    WolfCrypt testGCM = new WolfCrypt();
                    int[] timesAESGCM = testGCM.AESGCM(blocksize);

                    System.out.println("Time to encrypt:" + timesAESGCM[0] + "ms\n");
                    writer.write("Time to encrypt:" + timesAESGCM[0] + "ms\n");


                    System.out.println("Time to decrypt:" + timesAESGCM[1] + "ms\n");
                    writer.write("Time to decrypt:" + timesAESGCM[1] + "ms\n");

                    writer.write(separate);



                    String wcmd5= "***********MD5**************" + "\n";
                    System.out.println(wcmd5);
                    writer.write(wcmd5);

                    WolfCrypt testmd5 = new WolfCrypt();
                    int[] timesmd5 = testmd5.MD5(64);

                    System.out.println("Time to generate hash:" + timesmd5[1] + "ms\n");
                    writer.write("Time to generate hash: " + timesmd5[1] + "ms\n");


                    writer.write(separate);



                    blocksize = blocksize*2;
                }

                String wcdh= "***********DH**************" + "\n";
                System.out.println(wcdh);
                writer.write(wcdh);

                WolfCrypt testDHwc = new WolfCrypt();
                timesDH = testDHwc.DH();

                System.out.println("Time to key agreement:" + timesDH[1] + "ms\n");
                writer.write("Time to key agreement" + timesDH[1] + "ms\n");


                writer.write(separate);

                String wcecdh= "***********ECDH**************" + "\n";
                System.out.println(wcecdh);
                writer.write(wcecdh);

                WolfCrypt testECDHwc = new WolfCrypt();
                timesECDH = testECDHwc.ECDH();

                System.out.println("Time to key agreement:" + timesECDH[1] + "ms\n");
                writer.write("Time to key agreement" + timesECDH[1] + "ms\n");


                writer.write(separate);

                String wcRSA= "***********RSA**************" + "\n";
                System.out.println(wcRSA);
                writer.write(wcRSA);

                WolfCrypt testRSAwc = new WolfCrypt();
                timesRSA = testRSAwc.RSA(128);

                System.out.println("Time to encrypt:" + timesRSA[0] + "ms\n");
                writer.write("Time to encrypt:" + timesRSA[0] + "ms\n");


                System.out.println("Time to decrypt:" + timesRSA[1] + "ms\n");
                writer.write("Time to decrypt:" + timesRSA[1] + "ms\n");
                ;

                writer.write(separate_lib);


                String openssl = "***********OpenSSL**************" + "\n";
                System.out.println(openssl);
                writer.write(openssl);

                for (int blocksize = 128; blocksize <= 1024;){

                    String block = "*************BLOCKSIZE: " + blocksize +"******************" + "\n";
                    writer.write(block);


                    String wcmd5= "***********MD5**************" + "\n";
                    System.out.println(wcmd5);
                    writer.write(wcmd5);

                    OpenSSL testmd5 = new OpenSSL();
                    int[] timesmd5 = testmd5.MD5(blocksize);

                    System.out.println("Time to generate hash:" + timesmd5[0] + "ms\n");
                    writer.write("Time to generate hash: " + timesmd5[0] + "ms\n");

                    writer.write(separate);

                    String openCBC= "***********AES/CBC**************" + "\n";
                    System.out.println(openCBC);
                    writer.write(openCBC);

                    OpenSSL test = new OpenSSL();
                    int[] timesAES = test.AESCBC(blocksize);

                    System.out.println("Time to encrypt:" + timesAES[0] + "ms\n");
                    writer.write("Time to encrypt:" + timesAES[0] + "ms\n");


                    System.out.println("Time to decrypt:" + timesAES[1] + "ms\n");
                    writer.write("Time to decrypt:" + timesAES[1] + "ms\n");


                    writer.write(separate);

                    String mbedCTR= "***********AES/CTR**************" + "\n";
                    System.out.println(mbedCTR);
                    writer.write(mbedCTR);

                    OpenSSL testCTR = new OpenSSL();
                    int[] timesAESCTR = testCTR.AESCTR(blocksize);

                    System.out.println("Time to encrypt:" + timesAESCTR[0] + "ms\n");
                    writer.write("Time to encrypt:" + timesAESCTR[0] + "ms\n");


                    System.out.println("Time to decrypt:" + timesAESCTR[1] + "ms\n");
                    writer.write("Time to decrypt:" + timesAESCTR[1] + "ms\n");


                    writer.write(separate);

                    String mbedGCM= "***********AES/GCM**************" + "\n";
                    System.out.println(mbedGCM);
                    writer.write(mbedGCM);

                    OpenSSL testGCM = new OpenSSL();
                    int[] timesAESGCM = testGCM.AESGCM(blocksize);

                    System.out.println("Time to encrypt:" + timesAESGCM[0] + "ms\n");
                    writer.write("Time to encrypt:" + timesAESGCM[0] + "ms\n");


                    System.out.println("Time to decrypt:" + timesAESGCM[1] + "ms\n");
                    writer.write("Time to decrypt:" + timesAESGCM[1] + "ms\n");

                    writer.write(separate);

                    String openOFB= "***********AES/OFB**************" + "\n";
                    System.out.println(openOFB);
                    writer.write(openOFB);

                    OpenSSL testofb = new OpenSSL();
                    int[] timesAESOFB = testofb.AESOFB(blocksize);

                    System.out.println("Time to encrypt:" + timesAESOFB[0] + "ms\n");
                    writer.write("Time to encrypt:" + timesAESOFB[0] + "ms\n");


                    System.out.println("Time to decrypt:" + timesAESOFB[1] + "ms\n");
                    writer.write("Time to decrypt:" + timesAESOFB[1] + "ms\n");

                    writer.write(separate);

                    blocksize = blocksize*2;
                }

                String opendh= "***********DH**************" + "\n";
                System.out.println(opendh);
                writer.write(opendh);

                OpenSSL testDHopen = new OpenSSL();
                timesDH = testDHopen.DH();

                System.out.println("Time to key agreement:" + timesDH[1] + "ms\n");
                writer.write("Time to key agreement" + timesDH[1] + "ms\n");


                writer.write(separate);

                String openecdh= "***********ECDH**************" + "\n";
                System.out.println(openecdh);
                writer.write(openecdh);

                OpenSSL testECDHopen = new OpenSSL();
                timesECDH = testECDHopen.ECDH();

                System.out.println("Time to key agreement:" + timesECDH[1] + "ms\n");
                writer.write("Time to key agreement" + timesECDH[1] + "ms\n");


                writer.write(separate);

                String openRSA= "***********RSA**************" + "\n";
                System.out.println(openRSA);
                writer.write(openRSA);

                OpenSSL testRSA = new OpenSSL();
                timesRSA = testRSA.RSA(128);

                System.out.println("Time to encrypt:" + timesRSA[0] + "ms\n");
                writer.write("Time to encrypt:" + timesRSA[0] + "ms\n");


                System.out.println("Time to decrypt:" + timesRSA[1] + "ms\n");
                writer.write("Time to decrypt:" + timesRSA[1] + "ms\n");


                writer.write(separate_lib);

                String boringssl = "***********BoringSSL**************" + "\n";
                System.out.println(boringssl);
                writer.write(boringssl);



                for (int blocksize = 128; blocksize <= 1024;){

                    String block = "*************BLOCKSIZE: " + blocksize +"******************" + "\n";
                    writer.write(block);

                    String wcmd5= "***********MD5**************" + "\n";
                    System.out.println(wcmd5);
                    writer.write(wcmd5);

                    BoringSSL testmd5 = new BoringSSL();
                    int[] timesmd5 = testmd5.MD5(blocksize);

                    System.out.println("Time to generate hash:" + timesmd5[1] + "ms\n");
                    writer.write("Time to generate hash: " + timesmd5[1] + "ms\n");


                    writer.write(separate);


                    String openCBC= "***********AES/CBC**************" + "\n";
                    System.out.println(openCBC);
                    writer.write(openCBC);

                    BoringSSL test = new BoringSSL();
                    int[] timesAES = test.AESCBC(blocksize);

                    System.out.println("Time to encrypt:" + timesAES[0] + "ms\n");
                    writer.write("Time to encrypt:" + timesAES[0] + "ms\n");


                    System.out.println("Time to decrypt:" + timesAES[1] + "ms\n");
                    writer.write("Time to decrypt:" + timesAES[1] + "ms\n");


                    writer.write(separate);

                    String mbedCTR= "***********AES/CTR**************" + "\n";
                    System.out.println(mbedCTR);
                    writer.write(mbedCTR);

                    BoringSSL testCTR = new BoringSSL();
                    int[] timesAESCTR = testCTR.AESCTR(blocksize);

                    System.out.println("Time to encrypt:" + timesAESCTR[0] + "ms\n");
                    writer.write("Time to encrypt:" + timesAESCTR[0] + "ms\n");


                    System.out.println("Time to decrypt:" + timesAESCTR[1] + "ms\n");
                    writer.write("Time to decrypt:" + timesAESCTR[1] + "ms\n");


                    writer.write(separate);

                    String mbedGCM= "***********AES/GCM**************" + "\n";
                    System.out.println(mbedGCM);
                    writer.write(mbedGCM);

                    BoringSSL testGCM = new BoringSSL();
                    int[] timesAESGCM = testGCM.AESGCM(blocksize);

                    System.out.println("Time to encrypt:" + timesAESGCM[0] + "ms\n");
                    writer.write("Time to encrypt:" + timesAESGCM[0] + "ms\n");


                    System.out.println("Time to decrypt:" + timesAESGCM[1] + "ms\n");
                    writer.write("Time to decrypt:" + timesAESGCM[1] + "ms\n");

                    writer.write(separate);

                    String openOFB= "***********AES/OFB**************" + "\n";
                    System.out.println(openOFB);
                    writer.write(openOFB);

                    BoringSSL testofb = new BoringSSL();
                    int[] timesAESOFB = testofb.AESOFB(blocksize);

                    System.out.println("Time to encrypt:" + timesAESOFB[0] + "ms\n");
                    writer.write("Time to encrypt:" + timesAESOFB[0] + "ms\n");


                    System.out.println("Time to decrypt:" + timesAESOFB[1] + "ms\n");
                    writer.write("Time to decrypt:" + timesAESOFB[1] + "ms\n");

                    writer.write(separate);

                    blocksize = blocksize*2;
                }

                opendh= "***********DH**************" + "\n";
                System.out.println(opendh);
                writer.write(opendh);

                BoringSSL testDHboring = new BoringSSL();
                timesDH = testDHboring.DH();

                System.out.println("Time to key agreement:" + timesDH[1] + "ms\n");
                writer.write("Time to key agreement" + timesDH[1] + "ms\n");


                writer.write(separate);

                openecdh= "***********ECDH**************" + "\n";
                System.out.println(openecdh);
                writer.write(openecdh);

                BoringSSL testECDHboring = new BoringSSL();
                timesECDH = testECDHboring.ECDH();

                System.out.println("Time to key agreement:" + timesECDH[1] + "ms\n");
                writer.write("Time to key agreement" + timesECDH[1] + "ms\n");


                writer.write(separate);

                String wcRSAboring= "***********RSA**************" + "\n";
                System.out.println(wcRSAboring);
                writer.write(wcRSAboring);

                BoringSSL testRSAboring = new BoringSSL();
                timesRSA = testRSAboring.RSA(128);

                System.out.println("Time to encrypt:" + timesRSA[0] + "ms\n");
                writer.write("Time to encrypt:" + timesRSA[0] + "ms\n");


                System.out.println("Time to decrypt:" + timesRSA[1] + "ms\n");
                writer.write("Time to decrypt:" + timesRSA[1] + "ms\n");


                writer.write(separate_lib);

                }

            writer.close();

            final String title = System.getProperty("os.arch");
            final GMailSender sender = new GMailSender("encryptapp.report@gmail.com",
                    "EncryptAppReport");

            new AsyncTask<Void, Void, Void>() {
                @Override
                public Void doInBackground(Void... arg) {
                    try {
                        sender.sendMail("Report",
                                "Complete Test" + title,
                                "encr" +
                                        "yptapp.report@gmail.com",
                                "encryptapp.report@gmail.com",
                                report);
                        System.out.println("E-mail sent");
                    } catch (Exception e) {
                        Log.e("SendMail", e.getMessage(), e);
                    }
                    return null;
                }
            }.execute();




        } catch (IOException e){
            throw new RuntimeException(e);
        } catch(NoSuchAlgorithmException z){
            throw new RuntimeException(z);
        } catch (NoSuchProviderException w){
            throw new RuntimeException(w);
        } catch (InvalidAlgorithmParameterException v){
            throw new RuntimeException(v);
        } catch (NoSuchPaddingException y){
            throw new RuntimeException(y);
        } catch (IllegalBlockSizeException u){
            throw new RuntimeException(u);
        } catch (InvalidKeyException t){
            throw new RuntimeException(t);
        } catch (BadPaddingException p){
            throw new RuntimeException(p);
        }   catch (InvalidParameterSpecException x){
            throw new RuntimeException(x);
        }

        return results;
    }

    @Override
    protected void onPostExecute(final TextView report) {
            dialog.dismiss();
            report.setText("\n"+"\n"+"\n"+"\n"+"   Test finished successfully"+"\n"+"\n"+"  Find your results at " +
                    "CryptoBench/Report.txt");
        super.onPostExecute(report);
    }


}

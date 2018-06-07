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

import static com.example.juanperezdealgaba.sac.RSA.Decrypt;
import static com.example.juanperezdealgaba.sac.RSA.Encrypt;
import static com.example.juanperezdealgaba.sac.RSA.GenerateKeys;



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

            String device_data = "Super Test Results\n" + "*********************************\n"
                    + "Model CPU: " + model_cpu + "\n" + "Android Version:" + myVersion + "\n" +
                    "SDK Version: " + sdkVersion + "\n" + "Manufacturer: " + manufacturer + "\n" +
                    "Device: " + device + "\n" + "Model: " + model + "\n"
                    + "********************************\n\n";

            results.setText(device_data);
            writer.write("\n");
            writer.write("\n");
            writer.write("\n");
            String separate = "*********************************************" + "\n";

            for (int i= 0; i< repetitions; i++){


                String BC = "***********Bouncy Castle**************" + "\n";
                System.out.println(BC);
                results.append(BC);
                writer.write(BC);


                for (int blocksize = 2; blocksize <= 128;){


                    System.out.println("Blocksize is:");
                    System.out.println(blocksize);
                    String block = "*************BLOCKSIZE: " + blocksize +"******************" + "\n";
                    writer.write(block);
                    results.append(block);

                    String BCCBC= "***********AES/CBC**************" + "\n";
                    System.out.println(BCCBC);
                    results.append(BCCBC);
                    writer.write(BCCBC);

                    AESCBC testCBC = new AESCBC();
                    testCBC.testCBC(writer,results,blocksize);

                    writer.write(separate);
                    results.append(separate);

                    String BCCTR= "***********AES/CTR**************" + "\n";
                    System.out.println(BCCTR);
                    results.append(BCCTR);
                    writer.write(BCCTR);

                    AESCTR testCTR = new AESCTR();
                    testCTR.testCTR(writer, results, blocksize);

                    writer.write(separate);
                    results.append(separate);

                    String BCGCM= "***********AES/GCM**************" + "\n";
                    System.out.println(BCGCM);
                    results.append(BCGCM);
                    writer.write(BCGCM);

                    AESGCM testGCM = new AESGCM();
                    testGCM.testGCM(writer, results, blocksize);

                    writer.write(separate);
                    results.append(separate);

                    String BCOFB= "***********AES/OFB**************" + "\n";
                    System.out.println(BCOFB);
                    results.append(BCOFB);
                    writer.write(BCOFB);

                    AESOFB testOFB = new AESOFB();
                    testOFB.testOFB(writer, results, blocksize);

                    writer.write(separate);
                    results.append(separate);

                    String BCDH= "***********DH**************" + "\n";
                    System.out.println(BCDH);
                    results.append(BCDH);
                    writer.write(BCDH);

                    DiffieHellman testDH = new DiffieHellman();
                    testDH.testDH(writer, results);

                    writer.write(separate);
                    results.append(separate);

                    String BCECDH= "***********ECDH**************" + "\n";
                    System.out.println(BCECDH);
                    results.append(BCECDH);
                    writer.write(BCECDH);

                    ECDiffieHellmanImplementation testECDH = new ECDiffieHellmanImplementation();
                    testECDH.startDiffieHellman(writer, results);

                    writer.write(separate);
                    results.append(separate);

                    String BCMD5= "***********MD-5**************" + "\n";
                    System.out.println(BCMD5);
                    results.append(BCMD5);
                    writer.write(BCMD5);

                    RSAPrueba testRSA = new RSAPrueba();
                    testRSA.testRSA(writer, results,blocksize);

                    writer.write(separate);
                    results.append(separate);

                    String BCRSA= "***********RSA**************" + "\n";
                    System.out.println(BCRSA);
                    results.append(BCRSA);
                    writer.write(BCRSA);

                   MD5Implementation testmd5 = new MD5Implementation();
                    testmd5.testmd5(writer, results,blocksize);

                    writer.write(separate);
                    results.append(separate);

                    blocksize = blocksize*2;


                }

                String mbed = "***********mbedTLS**************" + "\n";
                System.out.println(mbed);
                results.append(mbed);
                writer.write(mbed);

                for (int blocksize = 2; blocksize <= 128;) {
                    String block = "*************BLOCKSIZE: " + blocksize +"******************" + "\n";
                    writer.write(block);
                    results.append(block);
                    String mbedCBC= "***********AES/CBC**************" + "\n";
                    System.out.println(mbedCBC);
                    results.append(mbedCBC);
                    writer.write(mbedCBC);

                    mbedTLS test = new mbedTLS();
                    int[] timesAES = test.AESCBC(blocksize);

                    System.out.println("Time to encrypt:" + timesAES[0] + "ns\n");
                    writer.write("Time to encrypt:" + timesAES[0] + "ns\n");
                    results.append("Time to encrypt:" + timesAES[0] + "ns\n");


                    System.out.println("Time to decrypt:" + timesAES[1] + "ns\n");
                    writer.write("Time to decrypt:" + timesAES[1] + "ns\n");
                    results.append("Time to decrypt:" + timesAES[1] + "ns\n");
                    results.append("\n");

                    writer.write(separate);
                    results.append(separate);

                    String mbedCTR= "***********AES/CTR**************" + "\n";
                    System.out.println(mbedCTR);
                    results.append(mbedCTR);
                    writer.write(mbedCTR);

                    mbedTLS testCTR = new mbedTLS();
                    int[] timesAESCTR = testCTR.AESCTR(blocksize);

                    System.out.println("Time to encrypt:" + timesAESCTR[0] + "ns\n");
                    writer.write("Time to encrypt:" + timesAESCTR[0] + "ns\n");
                    results.append("Time to encrypt:" + timesAESCTR[0] + "ns\n");


                    System.out.println("Time to decrypt:" + timesAESCTR[1] + "ns\n");
                    writer.write("Time to decrypt:" + timesAESCTR[1] + "ns\n");
                    results.append("Time to decrypt:" + timesAESCTR[1] + "ns\n");
                    results.append("\n");

                    writer.write(separate);
                    results.append(separate);

                    String mbedGCM= "***********AES/GCM**************" + "\n";
                    System.out.println(mbedGCM);
                    results.append(mbedGCM);
                    writer.write(mbedGCM);

                    mbedTLS testGCM = new mbedTLS();
                    int[] timesAESGCM = testGCM.AESGCM(blocksize);

                    System.out.println("Time to encrypt:" + timesAESGCM[0] + "ns\n");
                    writer.write("Time to encrypt:" + timesAESGCM[0] + "ns\n");
                    results.append("Time to encrypt:" + timesAESGCM[0] + "ns\n");


                    System.out.println("Time to decrypt:" + timesAESGCM[1] + "ns\n");
                    writer.write("Time to decrypt:" + timesAESGCM[1] + "ns\n");
                    results.append("Time to decrypt:" + timesAESGCM[1] + "ns\n");
                    results.append("\n");

                    writer.write(separate);
                    results.append(separate);

                    String mbeddh= "***********DH**************" + "\n";
                    System.out.println(mbeddh);
                    results.append(mbeddh);
                    writer.write(mbeddh);

                    mbedTLS testDH = new mbedTLS();
                    int[] timesDH = testDH.DH();

                    System.out.println("Time to key agreement:" + timesDH[1] + "ms\n");
                    writer.write("Time to key agreement" + timesDH[1] + "ms\n");
                    results.append("Time to key agreement:" + timesDH[1] + "ms\n");
                    results.append("\n");

                    writer.write(separate);
                    results.append(separate);

                    String mbedecdh= "***********ECDH**************" + "\n";
                    System.out.println(mbedecdh);
                    results.append(mbedecdh);
                    writer.write(mbedecdh);

                    mbedTLS testECDH = new mbedTLS();
                    int[] timesECDH = testECDH.ECDH();

                    System.out.println("Time to key agreement:" + timesECDH[1] + "ms\n");
                    writer.write("Time to key agreement" + timesECDH[1] + "ms\n");
                    results.append("Time to key agreement:" + timesECDH[1] + "ms\n");
                    results.append("\n");

                    writer.write(separate);
                    results.append(separate);

                    String mbedRSA= "***********RSA**************" + "\n";
                    System.out.println(mbedRSA);
                    results.append(mbedRSA);
                    writer.write(mbedRSA);

                    mbedTLS testRSA = new mbedTLS();
                    int[] timesRSA = testRSA.RSA(blocksize);

                    System.out.println("Time to encrypt:" + timesRSA[0] + "ns\n");
                    writer.write("Time to encrypt:" + timesRSA[0] + "ns\n");
                    results.append("Time to encrypt:" + timesRSA[0] + "ns\n");


                    System.out.println("Time to decrypt:" + timesRSA[1] + "ns\n");
                    writer.write("Time to decrypt:" + timesRSA[1] + "ns\n");
                    results.append("Time to decrypt:" + timesRSA[1] + "ns\n");
                    results.append("\n");

                    writer.write(separate);
                    results.append(separate);

                    String mbedmd5= "***********MD5**************" + "\n";
                    System.out.println(mbedmd5);
                    results.append(mbedmd5);
                    writer.write(mbedmd5);

                    mbedTLS testmd5 = new mbedTLS();
                    int[] timesmd5 = testmd5.MD5(blocksize);

                    System.out.println("Time to generate hash:" + timesmd5[1] + "ms\n");
                    writer.write("Time to generate hash" + timesmd5[1] + "ms\n");
                    results.append("Time to generate hash" + timesmd5[1] + "ms\n");
                    results.append("\n");

                    writer.write(separate);
                    results.append(separate);

                    blocksize = blocksize*2;

                }

                String wc = "***********WolfCrypt**************" + "\n";
                System.out.println(wc);
                results.append(wc);
                writer.write(wc);

                for (int blocksize = 2; blocksize <= 128;){
                    String block = "*************BLOCKSIZE: " + blocksize +"******************" + "\n";
                    writer.write(block);
                    results.append(block);


                    String wcCBC= "***********AES/CBC**************" + "\n";
                    System.out.println(wcCBC);
                    results.append(wcCBC);
                    writer.write(wcCBC);

                    WolfCrypt test = new WolfCrypt();
                    int[] timesAES = test.AESCBC(blocksize);

                    System.out.println("Time to encrypt:" + timesAES[0] + "ns\n");
                    writer.write("Time to encrypt:" + timesAES[0] + "ns\n");
                    results.append("Time to encrypt:" + timesAES[0] + "ns\n");


                    System.out.println("Time to decrypt:" + timesAES[1] + "ns\n");
                    writer.write("Time to decrypt:" + timesAES[1] + "ns\n");
                    results.append("Time to decrypt:" + timesAES[1] + "ns\n");
                    results.append("\n");

                    writer.write(separate);
                    results.append(separate);

                    String mbedCTR= "***********AES/CTR**************" + "\n";
                    System.out.println(mbedCTR);
                    results.append(mbedCTR);
                    writer.write(mbedCTR);

                    WolfCrypt testCTR = new WolfCrypt();
                    int[] timesAESCTR = testCTR.AESCTR(blocksize);

                    System.out.println("Time to encrypt:" + timesAESCTR[0] + "ns\n");
                    writer.write("Time to encrypt:" + timesAESCTR[0] + "ns\n");
                    results.append("Time to encrypt:" + timesAESCTR[0] + "ns\n");


                    System.out.println("Time to decrypt:" + timesAESCTR[1] + "ns\n");
                    writer.write("Time to decrypt:" + timesAESCTR[1] + "ns\n");
                    results.append("Time to decrypt:" + timesAESCTR[1] + "ns\n");
                    results.append("\n");

                    writer.write(separate);
                    results.append(separate);

                    String mbedGCM= "***********AES/GCM**************" + "\n";
                    System.out.println(mbedGCM);
                    results.append(mbedGCM);
                    writer.write(mbedGCM);

                    WolfCrypt testGCM = new WolfCrypt();
                    int[] timesAESGCM = testGCM.AESGCM(blocksize);

                    System.out.println("Time to encrypt:" + timesAESGCM[0] + "ns\n");
                    writer.write("Time to encrypt:" + timesAESGCM[0] + "ns\n");
                    results.append("Time to encrypt:" + timesAESGCM[0] + "ns\n");


                    System.out.println("Time to decrypt:" + timesAESGCM[1] + "ns\n");
                    writer.write("Time to decrypt:" + timesAESGCM[1] + "ns\n");
                    results.append("Time to decrypt:" + timesAESGCM[1] + "ns\n");
                    results.append("\n");

                    writer.write(separate);
                    results.append(separate);

                    String wcdh= "***********DH**************" + "\n";
                    System.out.println(wcdh);
                    results.append(wcdh);
                    writer.write(wcdh);

                    WolfCrypt testDH = new WolfCrypt();
                    int[] timesDH = testDH.DH();

                    System.out.println("Time to key agreement:" + timesDH[1] + "ms\n");
                    writer.write("Time to key agreement" + timesDH[1] + "ms\n");
                    results.append("Time to key agreement:" + timesDH[1] + "ms\n");
                    results.append("\n");

                    writer.write(separate);
                    results.append(separate);

                    String wcecdh= "***********ECDH**************" + "\n";
                    System.out.println(wcecdh);
                    results.append(wcecdh);
                    writer.write(wcecdh);

                    WolfCrypt testECDH = new WolfCrypt();
                    int[] timesECDH = testECDH.ECDH();

                    System.out.println("Time to key agreement:" + timesECDH[1] + "ms\n");
                    writer.write("Time to key agreement" + timesECDH[1] + "ms\n");
                    results.append("Time to key agreement:" + timesECDH[1] + "ms\n");
                    results.append("\n");

                    writer.write(separate);
                    results.append(separate);

                    String wcmd5= "***********MD5**************" + "\n";
                    System.out.println(wcmd5);
                    results.append(wcmd5);
                    writer.write(wcmd5);

                    WolfCrypt testmd5 = new WolfCrypt();
                    int[] timesmd5 = testmd5.MD5(64);

                    System.out.println("Time to generate hash:" + timesmd5[1] + "ms\n");
                    writer.write("Time to generate hash" + timesmd5[1] + "ms\n");
                    results.append("Time to generate hash" + timesmd5[1] + "ms\n");
                    results.append("\n");

                    writer.write(separate);
                    results.append(separate);

                    String wcRSA= "***********RSA**************" + "\n";
                    System.out.println(wcRSA);
                    results.append(wcRSA);
                    writer.write(wcRSA);

                    WolfCrypt testRSA = new WolfCrypt();
                    int[] timesRSA = testRSA.RSA(blocksize);

                    System.out.println("Time to encrypt:" + timesRSA[0] + "ns\n");
                    writer.write("Time to encrypt:" + timesRSA[0] + "ns\n");
                    results.append("Time to encrypt:" + timesRSA[0] + "ns\n");


                    System.out.println("Time to decrypt:" + timesRSA[1] + "ns\n");
                    writer.write("Time to decrypt:" + timesRSA[1] + "ns\n");
                    results.append("Time to decrypt:" + timesRSA[1] + "ns\n");
                    results.append("\n");

                    writer.write(separate);
                    results.append(separate);

                    blocksize = blocksize*2;
                }

                String openssl = "***********OpenSSL**************" + "\n";
                System.out.println(openssl);
                results.append(openssl);
                writer.write(openssl);

                for (int blocksize = 2; blocksize <= 128;){

                    String block = "*************BLOCKSIZE: " + blocksize +"******************" + "\n";
                    writer.write(block);
                    results.append(block);


                    String wcmd5= "***********MD5**************" + "\n";
                    System.out.println(wcmd5);
                    results.append(wcmd5);
                    writer.write(wcmd5);

                    OpenSSL testmd5 = new OpenSSL();
                    int[] timesmd5 = testmd5.MD5(blocksize);

                    System.out.println("Time to generate hash:" + timesmd5[0] + "ms\n");
                    writer.write("Time to generate hash" + timesmd5[0] + "ms\n");
                    results.append("Time to generate hash" + timesmd5[0] + "ms\n");
                    results.append("\n");

                    writer.write(separate);
                    results.append(separate);

                    String wcRSA= "***********RSA**************" + "\n";
                    System.out.println(wcRSA);
                    results.append(wcRSA);
                    writer.write(wcRSA);

                    OpenSSL testRSA = new OpenSSL();
                    int[] timesRSA = testRSA.RSA(blocksize);

                    System.out.println("Time to encrypt:" + timesRSA[0] + "ns\n");
                    writer.write("Time to encrypt:" + timesRSA[0] + "ns\n");
                    results.append("Time to encrypt:" + timesRSA[0] + "ns\n");


                    System.out.println("Time to decrypt:" + timesRSA[1] + "ns\n");
                    writer.write("Time to decrypt:" + timesRSA[1] + "ns\n");
                    results.append("Time to decrypt:" + timesRSA[1] + "ns\n");
                    results.append("\n");

                    writer.write(separate);
                    results.append(separate);

                    String opendh= "***********DH**************" + "\n";
                    System.out.println(opendh);
                    results.append(opendh);
                    writer.write(opendh);

                    OpenSSL testDH = new OpenSSL();
                    int[] timesDH = testDH.DH();

                    System.out.println("Time to key agreement:" + timesDH[1] + "ms\n");
                    writer.write("Time to key agreement" + timesDH[1] + "ms\n");
                    results.append("Time to key agreement:" + timesDH[1] + "ms\n");
                    results.append("\n");

                    writer.write(separate);
                    results.append(separate);

                    String openecdh= "***********ECDH**************" + "\n";
                    System.out.println(openecdh);
                    results.append(openecdh);
                    writer.write(openecdh);

                    OpenSSL testECDH = new OpenSSL();
                    int[] timesECDH = testECDH.ECDH();

                    System.out.println("Time to key agreement:" + timesECDH[1] + "ms\n");
                    writer.write("Time to key agreement" + timesECDH[1] + "ms\n");
                    results.append("Time to key agreement:" + timesECDH[1] + "ms\n");
                    results.append("\n");

                    writer.write(separate);
                    results.append(separate);

                    String openCBC= "***********AES/CBC**************" + "\n";
                    System.out.println(openCBC);
                    results.append(openCBC);
                    writer.write(openCBC);

                    OpenSSL test = new OpenSSL();
                    int[] timesAES = test.AESCBC(blocksize);

                    System.out.println("Time to encrypt:" + timesAES[0] + "ns\n");
                    writer.write("Time to encrypt:" + timesAES[0] + "ns\n");
                    results.append("Time to encrypt:" + timesAES[0] + "ns\n");


                    System.out.println("Time to decrypt:" + timesAES[1] + "ns\n");
                    writer.write("Time to decrypt:" + timesAES[1] + "ns\n");
                    results.append("Time to decrypt:" + timesAES[1] + "ns\n");
                    results.append("\n");

                    writer.write(separate);
                    results.append(separate);

                    String mbedCTR= "***********AES/CTR**************" + "\n";
                    System.out.println(mbedCTR);
                    results.append(mbedCTR);
                    writer.write(mbedCTR);

                    OpenSSL testCTR = new OpenSSL();
                    int[] timesAESCTR = testCTR.AESCTR(blocksize);

                    System.out.println("Time to encrypt:" + timesAESCTR[0] + "ns\n");
                    writer.write("Time to encrypt:" + timesAESCTR[0] + "ns\n");
                    results.append("Time to encrypt:" + timesAESCTR[0] + "ns\n");


                    System.out.println("Time to decrypt:" + timesAESCTR[1] + "ns\n");
                    writer.write("Time to decrypt:" + timesAESCTR[1] + "ns\n");
                    results.append("Time to decrypt:" + timesAESCTR[1] + "ns\n");
                    results.append("\n");

                    writer.write(separate);
                    results.append(separate);

                    String mbedGCM= "***********AES/GCM**************" + "\n";
                    System.out.println(mbedGCM);
                    results.append(mbedGCM);
                    writer.write(mbedGCM);

                    OpenSSL testGCM = new OpenSSL();
                    int[] timesAESGCM = testGCM.AESGCM(blocksize);

                    System.out.println("Time to encrypt:" + timesAESGCM[0] + "ns\n");
                    writer.write("Time to encrypt:" + timesAESGCM[0] + "ns\n");
                    results.append("Time to encrypt:" + timesAESGCM[0] + "ns\n");


                    System.out.println("Time to decrypt:" + timesAESGCM[1] + "ns\n");
                    writer.write("Time to decrypt:" + timesAESGCM[1] + "ns\n");
                    results.append("Time to decrypt:" + timesAESGCM[1] + "ns\n");
                    results.append("\n");

                    writer.write(separate);
                    results.append(separate);

                    String openOFB= "***********AES/OFB**************" + "\n";
                    System.out.println(openOFB);
                    results.append(openOFB);
                    writer.write(openOFB);

                    OpenSSL testofb = new OpenSSL();
                    int[] timesAESOFB = testofb.AESOFB(blocksize);

                    System.out.println("Time to encrypt:" + timesAESOFB[0] + "ns\n");
                    writer.write("Time to encrypt:" + timesAESOFB[0] + "ns\n");
                    results.append("Time to encrypt:" + timesAESOFB[0] + "ns\n");


                    System.out.println("Time to decrypt:" + timesAESOFB[1] + "ns\n");
                    writer.write("Time to decrypt:" + timesAESOFB[1] + "ns\n");
                    results.append("Time to decrypt:" + timesAESOFB[1] + "ns\n");
                    results.append("\n");

                    writer.write(separate);
                    results.append(separate);

                    blocksize = blocksize*2;
                }

                String boringssl = "***********BoringSSL**************" + "\n";
                System.out.println(boringssl);
                results.append(boringssl);
                writer.write(boringssl);



                for (int blocksize = 2; blocksize <= 128;){

                    String block = "*************BLOCKSIZE: " + blocksize +"******************" + "\n";
                    writer.write(block);
                    results.append(block);

                    String wcmd5= "***********MD5**************" + "\n";
                    System.out.println(wcmd5);
                    results.append(wcmd5);
                    writer.write(wcmd5);

                    BoringSSL testmd5 = new BoringSSL();
                    int[] timesmd5 = testmd5.MD5(blocksize);

                    System.out.println("Time to generate hash:" + timesmd5[1] + "ms\n");
                    writer.write("Time to generate hash" + timesmd5[1] + "ms\n");
                    results.append("Time to generate hash" + timesmd5[1] + "ms\n");
                    results.append("\n");

                    writer.write(separate);
                    results.append(separate);

                    String wcRSA= "***********RSA**************" + "\n";
                    System.out.println(wcRSA);
                    results.append(wcRSA);
                    writer.write(wcRSA);

                    BoringSSL testRSA = new BoringSSL();
                    int[] timesRSA = testRSA.RSA(blocksize);

                    System.out.println("Time to encrypt:" + timesRSA[0] + "ns\n");
                    writer.write("Time to encrypt:" + timesRSA[0] + "ns\n");
                    results.append("Time to encrypt:" + timesRSA[0] + "ns\n");


                    System.out.println("Time to decrypt:" + timesRSA[1] + "ns\n");
                    writer.write("Time to decrypt:" + timesRSA[1] + "ns\n");
                    results.append("Time to decrypt:" + timesRSA[1] + "ns\n");
                    results.append("\n");

                    writer.write(separate);
                    results.append(separate);

                    String opendh= "***********DH**************" + "\n";
                    System.out.println(opendh);
                    results.append(opendh);
                    writer.write(opendh);

                    BoringSSL testDH = new BoringSSL();
                    int[] timesDH = testDH.DH();

                    System.out.println("Time to key agreement:" + timesDH[1] + "ms\n");
                    writer.write("Time to key agreement" + timesDH[1] + "ms\n");
                    results.append("Time to key agreement:" + timesDH[1] + "ms\n");
                    results.append("\n");

                    writer.write(separate);
                    results.append(separate);

                    String openecdh= "***********ECDH**************" + "\n";
                    System.out.println(openecdh);
                    results.append(openecdh);
                    writer.write(openecdh);

                    BoringSSL testECDH = new BoringSSL();
                    int[] timesECDH = testECDH.ECDH();

                    System.out.println("Time to key agreement:" + timesECDH[1] + "ms\n");
                    writer.write("Time to key agreement" + timesECDH[1] + "ms\n");
                    results.append("Time to key agreement:" + timesECDH[1] + "ms\n");
                    results.append("\n");

                    writer.write(separate);
                    results.append(separate);

                    String openCBC= "***********AES/CBC**************" + "\n";
                    System.out.println(openCBC);
                    results.append(openCBC);
                    writer.write(openCBC);

                    BoringSSL test = new BoringSSL();
                    int[] timesAES = test.AESCBC(blocksize);

                    System.out.println("Time to encrypt:" + timesAES[0] + "ns\n");
                    writer.write("Time to encrypt:" + timesAES[0] + "ns\n");
                    results.append("Time to encrypt:" + timesAES[0] + "ns\n");


                    System.out.println("Time to decrypt:" + timesAES[1] + "ns\n");
                    writer.write("Time to decrypt:" + timesAES[1] + "ns\n");
                    results.append("Time to decrypt:" + timesAES[1] + "ns\n");
                    results.append("\n");

                    writer.write(separate);
                    results.append(separate);

                    String mbedCTR= "***********AES/CTR**************" + "\n";
                    System.out.println(mbedCTR);
                    results.append(mbedCTR);
                    writer.write(mbedCTR);

                    BoringSSL testCTR = new BoringSSL();
                    int[] timesAESCTR = testCTR.AESCTR(blocksize);

                    System.out.println("Time to encrypt:" + timesAESCTR[0] + "ns\n");
                    writer.write("Time to encrypt:" + timesAESCTR[0] + "ns\n");
                    results.append("Time to encrypt:" + timesAESCTR[0] + "ns\n");


                    System.out.println("Time to decrypt:" + timesAESCTR[1] + "ns\n");
                    writer.write("Time to decrypt:" + timesAESCTR[1] + "ns\n");
                    results.append("Time to decrypt:" + timesAESCTR[1] + "ns\n");
                    results.append("\n");

                    writer.write(separate);
                    results.append(separate);

                    String mbedGCM= "***********AES/GCM**************" + "\n";
                    System.out.println(mbedGCM);
                    results.append(mbedGCM);
                    writer.write(mbedGCM);

                    BoringSSL testGCM = new BoringSSL();
                    int[] timesAESGCM = testGCM.AESGCM(blocksize);

                    System.out.println("Time to encrypt:" + timesAESGCM[0] + "ns\n");
                    writer.write("Time to encrypt:" + timesAESGCM[0] + "ns\n");
                    results.append("Time to encrypt:" + timesAESGCM[0] + "ns\n");


                    System.out.println("Time to decrypt:" + timesAESGCM[1] + "ns\n");
                    writer.write("Time to decrypt:" + timesAESGCM[1] + "ns\n");
                    results.append("Time to decrypt:" + timesAESGCM[1] + "ns\n");
                    results.append("\n");

                    writer.write(separate);
                    results.append(separate);

                    String openOFB= "***********AES/OFB**************" + "\n";
                    System.out.println(openOFB);
                    results.append(openOFB);
                    writer.write(openOFB);

                    BoringSSL testofb = new BoringSSL();
                    int[] timesAESOFB = testofb.AESOFB(blocksize);

                    System.out.println("Time to encrypt:" + timesAESOFB[0] + "ns\n");
                    writer.write("Time to encrypt:" + timesAESOFB[0] + "ns\n");
                    results.append("Time to encrypt:" + timesAESOFB[0] + "ns\n");


                    System.out.println("Time to decrypt:" + timesAESOFB[1] + "ns\n");
                    writer.write("Time to decrypt:" + timesAESOFB[1] + "ns\n");
                    results.append("Time to decrypt:" + timesAESOFB[1] + "ns\n");
                    results.append("\n");

                    writer.write(separate);
                    results.append(separate);

                    blocksize = blocksize*2;
                }

                }

            writer.close();

            final String titel = System.getProperty("os.arch");
            final GMailSender sender = new GMailSender("encryptapp.report@gmail.com",
                    "EncryptAppReport");

            new AsyncTask<Void, Void, Void>() {
                @Override
                public Void doInBackground(Void... arg) {
                    try {
                        sender.sendMail("Report",
                                "Special Test",
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
        super.onPostExecute(report);
    }


}

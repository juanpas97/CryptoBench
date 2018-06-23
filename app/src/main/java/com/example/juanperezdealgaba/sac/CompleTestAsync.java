package com.example.juanperezdealgaba.sac;

import android.app.ProgressDialog;
import android.os.AsyncTask;
import android.os.Build;
import android.util.Log;
import android.widget.TextView;

import com.snatik.storage.Storage;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidParameterSpecException;
import java.util.Calendar;
import java.util.Date;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;





class CompleteTestParams {
    FileWriter writer;
    TextView results;
    int repetitions;
    Storage storage;
    int rep_hash;
    int rep_agree;
    int rep_rsa;
    int rep_aes;

    CompleteTestParams(Storage storage, TextView results, int repetitions,int rep_aes,int rep_hash, int rep_agree, int rep_rsa) {

        this.storage = storage;
        this.results = results;
        this.repetitions = repetitions;
        this.rep_aes = rep_aes;
        this.rep_rsa = rep_rsa;
        this.rep_agree = rep_agree;
        this.rep_hash = rep_hash;
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
        int repetitions_aes = params[0].rep_aes;
        int repetitions_agree = params[0].rep_agree;
        int repetitions_rsa = params[0].rep_rsa;
        int repetitions_hash = params[0].rep_hash;

        try {


            int[] timesDH;
            String path = storage.getExternalStorageDirectory();

            final String newDir = path + File.separator + "CryptoBench";

            final File report = new File(newDir, "Report.txt");
            report.mkdirs();

            if (report.exists())
                report.delete();

            FileWriter writer = new FileWriter(report);


            String myVersion = android.os.Build.VERSION.RELEASE;
            int sdkVersion = android.os.Build.VERSION.SDK_INT;
            String manufacturer = Build.MANUFACTURER;
            String device = Build.DEVICE;
            String model = Build.MODEL;

            final String model_cpu = System.getProperty("os.arch");
            Date currentTime = Calendar.getInstance().getTime();

            writer.write("Super Test Results\n");
            writer.write("-----------------------------------\n");
            writer.write("CPU Model: " + model_cpu + "\n");
            writer.write("Android Version: " + myVersion + "\n");
            writer.write("SDK Version: " + sdkVersion + "\n");
            writer.write("Manufacturer: " + manufacturer + "\n");
            writer.write("Device: " + device + "\n");
            writer.write("Model: " + model + "\n");
            writer.write("Hour of test " + currentTime + "\n");

            writer.write("\n");
            writer.write("\n");
            writer.write("\n");
            String separate = "*********************************************" + "\n";
            String separate_lib = "*********************************************" + "\n"+ "\n"+ "\n"+ "\n";



                    String BC = "***********Bouncy Castle**************" + "\n";
                    System.out.println(BC);
                    writer.write(BC);


                    for (int blocksize = 128; blocksize <= 1024; ) {


                        System.out.println("Blocksize is:");
                        System.out.println(blocksize);
                        String block = "*************BLOCKSIZE: " + blocksize + "******************" + "\n";
                        writer.write(block);

                        String BCCBC = "***********AES/CBC**************" + "\n";
                        System.out.println(BCCBC);
                        writer.write(BCCBC);

                        AESCBC testCBC = new AESCBC();
                        testCBC.testCBC(writer, results, blocksize, repetitions_aes,repetitions);

                        writer.write(separate);

                        String BCCTR = "***********AES/CTR**************" + "\n";
                        System.out.println(BCCTR);
                        writer.write(BCCTR);

                        AESCTR testCTR = new AESCTR();
                        testCTR.testCTR(writer, results, blocksize, repetitions_aes,repetitions);

                        writer.write(separate);

                        String BCGCM = "***********AES/GCM**************" + "\n";
                        System.out.println(BCGCM);
                        writer.write(BCGCM);

                        AESGCM testGCM = new AESGCM();
                        testGCM.testGCM(writer, results, blocksize, repetitions_aes,repetitions);

                        writer.write(separate);

                        String BCOFB = "***********AES/OFB**************" + "\n";
                        System.out.println(BCOFB);
                        writer.write(BCOFB);

                        AESOFB testOFB = new AESOFB();
                        testOFB.testOFB(writer, results, blocksize, repetitions_aes,2);

                        writer.write(separate);


                        String BCMD5 = "***********MD-5**************" + "\n";
                        System.out.println(BCMD5);
                        writer.write(BCMD5);

                        MD5Implementation testmd5 = new MD5Implementation();
                        testmd5.testmd5(writer, results, blocksize, repetitions_hash,repetitions);

                        writer.write(separate);

                        blocksize = blocksize * 2;


                    }

                    String BCRSA = "***********RSA**************" + "\n";
                    System.out.println(BCRSA);
                    writer.write(BCRSA);


                    RSA testRSABC = new RSA();
                    testRSABC.testRSA(writer, results, 128, repetitions_rsa,repetitions);

                    writer.write(separate);

                    String BCDH = "***********DH**************" + "\n";
                    System.out.println(BCDH);
                    writer.write(BCDH);

                    DiffieHellman testDH = new DiffieHellman();
                    testDH.testDH(writer, results, repetitions_agree);

                    writer.write(separate);

                    String BCECDH = "***********ECDH**************" + "\n";
                    System.out.println(BCECDH);
                    writer.write(BCECDH);

                    ECDiffieHellmanImplementation testECDH = new ECDiffieHellmanImplementation();
                    testECDH.startDiffieHellman(writer, results, repetitions_agree,repetitions);

                    writer.write(separate_lib);

                    writer.close();

                    String mbed = "***********mbedTLS**************" + "\n";
                    System.out.println(mbed);


                    for (int blocksize = 128; blocksize <= 1024; ) {
                        String block = "*************BLOCKSIZE: " + blocksize + "******************" + "\n";
                        String mbedCBC = "***********AES/CBC**************" + "\n";
                        System.out.println(mbedCBC);

                        mbedTLS test = new mbedTLS();
                        test.AESCBC(blocksize, repetitions_aes,repetitions);


                        String mbedCTR = "***********AES/CTR**************" + "\n";
                        System.out.println(mbedCTR);

                        mbedTLS testCTR = new mbedTLS();
                        testCTR.AESCTR(blocksize, repetitions_aes,repetitions);


                        String mbedGCM = "***********AES/GCM**************" + "\n";
                        System.out.println(mbedGCM);


                            mbedTLS testGCM = new mbedTLS();
                            testGCM.AESGCM(blocksize, repetitions_aes,repetitions);


                        String mbedmd5 = "***********MD5**************" + "\n";
                        System.out.println(mbedmd5);

                        mbedTLS testmd5 = new mbedTLS();
                        testmd5.MD5(blocksize, repetitions_hash,repetitions);

                        blocksize = blocksize * 2;

                    }



                    String mbedRSA = "***********RSA**************" + "\n";
                    System.out.println(mbedRSA);

                    mbedTLS testRSAmbed = new mbedTLS();
                    testRSAmbed.RSA(128, repetitions_rsa,repetitions);


                    String mbeddh = "***********DH**************" + "\n";
                    System.out.println(mbeddh);


                    mbedTLS testDHmbed = new mbedTLS();
                    testDHmbed.DH(repetitions_agree,repetitions);


                    String mbedecdh = "***********ECDH**************" + "\n";
                    System.out.println(mbedecdh);

                    mbedTLS testECDHmbed = new mbedTLS();
                    testECDHmbed.ECDH(repetitions_agree,repetitions);


                    String wc = "***********WolfCrypt**************" + "\n";
                    System.out.println(wc);


                    for (int blocksize = 128; blocksize <= 1024; ) {

                        String block = "*************BLOCKSIZE: " + blocksize + "******************" + "\n";


                        String wcCBC = "***********AES/CBC**************" + "\n";
                        System.out.println(wcCBC);

                        WolfCrypt test = new WolfCrypt();
                        test.AESCBC(blocksize, repetitions_aes,repetitions);

                        String mbedCTR = "***********AES/CTR**************" + "\n";
                        System.out.println(mbedCTR);


                        WolfCrypt testCTR = new WolfCrypt();
                        testCTR.AESCTR(blocksize, repetitions_aes,repetitions);




                        String mbedGCM = "***********AES/GCM**************" + "\n";
                        System.out.println(mbedGCM);



                        WolfCrypt testGCM = new WolfCrypt();

                        testGCM.AESGCM(blocksize, repetitions_aes,repetitions);



                        String wcmd5 = "***********MD5**************" + "\n";
                        System.out.println(wcmd5);

                        WolfCrypt testmd5 = new WolfCrypt();
                        testmd5.MD5(blocksize, repetitions_hash,repetitions);

                        blocksize = blocksize * 2;
                    }


                    String wcdh = "***********DH**************" + "\n";
                    System.out.println(wcdh);


                    WolfCrypt testDHwc = new WolfCrypt();
                    testDHwc.DH(repetitions_agree,repetitions);

                    String wcecdh = "***********ECDH**************" + "\n";
                    System.out.println(wcecdh);

                    WolfCrypt testECDHwc = new WolfCrypt();
                    testECDHwc.ECDH(repetitions_agree,repetitions);


                    String wcRSA = "***********RSA**************" + "\n";
                    System.out.println(wcRSA);

                    WolfCrypt testRSAwc = new WolfCrypt();
                    testRSAwc.RSA(128, repetitions_rsa,repetitions);




                    String openssl = "***********OpenSSL**************" + "\n";
                    System.out.println(openssl);

                    for (int blocksize = 128; blocksize <= 1024; ) {

                        String block = "*************BLOCKSIZE: " + blocksize + "******************" + "\n";


                        String wcmd5 = "***********MD5**************" + "\n";
                        System.out.println(wcmd5);
                        OpenSSL testmd5 = new OpenSSL();
                        testmd5.MD5(blocksize, repetitions_hash,repetitions);


                        String openCBC = "***********AES/CBC**************" + "\n";
                        System.out.println(openCBC);

                        OpenSSL test = new OpenSSL();
                        test.AESCBC(blocksize, repetitions_aes,repetitions);

                        String mbedCTR = "***********AES/CTR**************" + "\n";
                        System.out.println(mbedCTR);

                        OpenSSL testCTR = new OpenSSL();
                        testCTR.AESCTR(blocksize, repetitions_aes,repetitions);



                        String mbedGCM = "***********AES/GCM**************" + "\n";
                        System.out.println(mbedGCM);

                        OpenSSL testGCM = new OpenSSL();
                        testGCM.AESGCM(blocksize, repetitions_aes,repetitions);



                        String openOFB = "***********AES/OFB**************" + "\n";
                        System.out.println(openOFB);

                        OpenSSL testofb = new OpenSSL();
                        testofb.AESOFB(blocksize, repetitions_aes,repetitions);


                        blocksize = blocksize * 2;
                    }




                    String opendh = "***********DH**************" + "\n";
                    System.out.println(opendh);

                    OpenSSL testDHopen = new OpenSSL();
                    testDHopen.DH(repetitions_agree,repetitions);


                    String openecdh = "***********ECDH**************" + "\n";
                    System.out.println(openecdh);

                    OpenSSL testECDHopen = new OpenSSL();
                    testECDHopen.ECDH(repetitions_agree,repetitions);

                    String openRSA = "***********RSA**************" + "\n";
                    System.out.println(openRSA);

                    OpenSSL testRSA = new OpenSSL();
                    testRSA.RSA(128, repetitions_rsa,repetitions);


                    String boringssl = "***********BoringSSL**************" + "\n";
                    System.out.println(boringssl);
                    writer.write(boringssl);


                    for (int blocksize = 128; blocksize <= 1024; ) {

                        String block = "*************BLOCKSIZE: " + blocksize + "******************" + "\n";
                        writer.write(block);

                        String wcmd5 = "***********MD5**************" + "\n";
                        System.out.println(wcmd5);
                        writer.write(wcmd5);

                        BoringSSL testmd5 = new BoringSSL();
                        testmd5.MD5(blocksize,repetitions_hash,repetitions);

                        String openCBC = "***********AES/CBC**************" + "\n";
                        System.out.println(openCBC);

                        BoringSSL test = new BoringSSL();
                        test.AESCBC(blocksize, repetitions_aes,repetitions);

                        String mbedCTR = "***********AES/CTR**************" + "\n";
                        System.out.println(mbedCTR);

                        BoringSSL testCTR = new BoringSSL();
                        testCTR.AESCTR(blocksize, repetitions_aes,repetitions);



                        String mbedGCM = "***********AES/GCM**************" + "\n";
                        System.out.println(mbedGCM);

                        BoringSSL testGCM = new BoringSSL();
                        testGCM.AESGCM(blocksize, repetitions_aes,repetitions);


                        String openOFB = "***********AES/OFB**************" + "\n";
                        System.out.println(openOFB);

                        BoringSSL testofb = new BoringSSL();
                        testofb.AESOFB(blocksize, repetitions_aes,repetitions);

                        blocksize = blocksize * 2;
                    }

                    opendh = "***********DH**************" + "\n";
                    System.out.println(opendh);

                    BoringSSL testDHboring = new BoringSSL();
                    testDHboring.DH(repetitions_agree,repetitions);



                    openecdh= "***********ECDH**************" + "\n";
                    System.out.println(openecdh);

                    BoringSSL testECDHboring = new BoringSSL();
                    testECDHboring.ECDH(repetitions_agree,repetitions);


                    String wcRSAboring= "***********RSA**************" + "\n";
                    System.out.println(wcRSAboring);

                    BoringSSL testRSAboring = new BoringSSL();
                    testRSAboring.RSA(128,repetitions_rsa,repetitions);


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
            report.setText("\n"+ "Test finished successfully"+"\n"+"\n"+"  Find your results at " +
                    "CryptoBench/Report.txt");
        super.onPostExecute(report);
    }


}

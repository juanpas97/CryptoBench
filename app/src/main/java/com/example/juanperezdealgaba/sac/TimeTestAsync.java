package com.example.juanperezdealgaba.sac;

import android.app.ProgressDialog;
import android.os.AsyncTask;
import android.os.Build;
import android.util.Log;
import android.widget.TextView;

import com.snatik.storage.Storage;

import java.io.FileWriter;
import java.io.IOException;

class TimeTestParams {
    String library;
    String algo;
    int blocksize;
    int time;
    int time_key;
    TextView results;
    FileWriter writer_special;

    TimeTestParams(FileWriter writer, TextView results, int time,int time_key,String library,String algo, int blocksize) {

        this.writer_special = writer;
        this.library = library;
        this.algo = algo;
        this.blocksize = blocksize;
        this.time = time;
        this.results = results;
        this.time_key = time_key;

    }
}


class TimeTestAsync extends AsyncTask<TimeTestParams, Void, TextView> {


    TimeTestAsync(ConcreteTest a){
        this.activity = a;
        dialog = new ProgressDialog(activity);
    }

    public  ConcreteTest activity;
    public ProgressDialog dialog;

    @Override
    protected void onPreExecute() {
        super.onPreExecute();
        dialog = new ProgressDialog(activity);
        dialog.setMessage("Performing benchmarks");
        dialog.show();
    }



    @Override
    protected TextView doInBackground(TimeTestParams... params) {
        FileWriter writer = params[0].writer_special;
        TextView results = params[0].results;
        int time = params[0].time;
        int blocksize = params[0].blocksize;
        String algo = params[0].algo;
        String library = params[0].library;
        int time_key = params[0].time_key;
        
        long startTime = System.currentTimeMillis();

        long maxDurationInMilliseconds = time * 60 * 1000;

        int sec_duration = ((int) maxDurationInMilliseconds / 1000);

        maxDurationInMilliseconds = time_key * 60 * 1000;

        int key_duration = ((int) maxDurationInMilliseconds / 1000) ;

        long resulttime = startTime + maxDurationInMilliseconds;
        int algo_repet = 0;
        try {

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


            if (library.equals("Bouncy Castle") && algo.equals("RSA")) {
                RSAPrueba test = new RSAPrueba();
                try {
                    test.testRSA(writer, results, blocksize,1);
                } catch (Exception i) {
                    throw new RuntimeException(i);
                }
            }

            if (library.equals("Bouncy Castle") && algo.equals("RSA2")) {
                RSAPrueba test = new RSAPrueba();
                try {
                    test.testRSA();
                } catch (Exception i) {
                    throw new RuntimeException(i);
                }
            }

            if (library.equals("Bouncy Castle") && algo.equals("AES-CBC")) {
                AESCBC test = new AESCBC();
                try {
                    test.testCBC(writer, results, blocksize,1 );
                } catch (Exception i) {
                    throw new RuntimeException(i);
                }
            }

            if (library.equals("Bouncy Castle") && algo.equals("AES-CTR")) {

                System.out.println("************Bouncy Castle/AES-CTR**************");
                writer.write("\n************Bouncy Castle/AES-CTR***************\n");

                while (System.currentTimeMillis() < startTime + maxDurationInMilliseconds) {
                    AESCTR test = new AESCTR();
                    try {
                        test.testCTR();
                    } catch (Exception i) {
                        throw new RuntimeException(i);
                    }
                }

                System.out.println("********************************");
                writer.write("********************************\n");
            }

            if (library.equals("Bouncy Castle") && algo.equals("AES-GCM")) {

                System.out.println("************Bouncy Castle/AES-GCM**************");
                writer.write("\n************Bouncy Castle/AES-GCM***************\n");

                while (System.currentTimeMillis() < startTime + maxDurationInMilliseconds) {
                    AESGCM test = new AESGCM();
                    try {
                        test.testGCM();
                    } catch (Exception i) {
                        throw new RuntimeException(i);
                    }
                }

                System.out.println("********************************");
                writer.write("********************************\n");
                results.append("********************************\n");
            }

            if (library.equals("Bouncy Castle") && algo.equals("AES-OFB")) {

                System.out.println("************Bouncy Castle/AES-OFB**************");
                writer.write("\n************Bouncy Castle/AES-OFB***************\n");

                while (System.currentTimeMillis() < startTime + maxDurationInMilliseconds) {
                    AESOFB test = new AESOFB();
                    try {
                        test.testOFB();
                    } catch (Exception i) {
                        throw new RuntimeException(i);
                    }
                }

                System.out.println("********************************");
                writer.write("********************************\n");
            }


            if (library.equals("Bouncy Castle") && algo.equals("MD5")) {
                while (System.currentTimeMillis() < startTime + maxDurationInMilliseconds) {
                    MD5Implementation test = new MD5Implementation();
                    try {
                        test.testmd5(writer, results, resulttime);
                    } catch (Exception i) {
                        throw new RuntimeException(i);
                    }
                }
            }

            if (library.equals("Bouncy Castle") && algo.equals("DH")) {
                while (System.currentTimeMillis() < startTime + maxDurationInMilliseconds) {
                    DiffieHellman test = new DiffieHellman();
                    try {
                        test.testDH();
                    } catch (Exception i) {
                        throw new RuntimeException(i);
                    }
                }
            }

            if (library.equals("Bouncy Castle") && algo.equals("ECDH")) {
                while (System.currentTimeMillis() < startTime + maxDurationInMilliseconds) {
                    ECDiffieHellmanImplementation test = new ECDiffieHellmanImplementation();
                    try {
                        test.startDiffieHellman(writer, results, resulttime);
                    } catch (Exception i) {
                        throw new RuntimeException(i);
                    }
                }
            }


            writer.close();

            if (library.equals("BoringSSL") && algo.equals("RSA")) {
                System.out.println("***********BoringSSL/RSA**************");


                    BoringSSL test = new BoringSSL();
                    test.RSATime(128,key_duration,sec_duration);


                System.out.println("***********************\n");
            }

            if (library.equals("BoringSSL") && algo.equals("AES-CBC")) {
                System.out.println("***********BoringSSL/AES-CBC**************");


                BoringSSL test = new BoringSSL();
                test.AESCBCTime(blocksize,key_duration,sec_duration);


                System.out.println("***********************\n");
            }

            if (library.equals("BoringSSL") && algo.equals("AES-CTR")) {
                System.out.println("***********BoringSSL/AES-CTR**************");

                    BoringSSL test = new BoringSSL();
                    test.AESCTRTime(blocksize,key_duration,sec_duration);

                System.out.println("***********************\n");
            }

            if (library.equals("BoringSSL") && algo.equals("AES-GCM")) {
                System.out.println("***********BoringSSL/AES-GCM**************");

                    BoringSSL test = new BoringSSL();
                    test.AESGCMTime(blocksize,key_duration,sec_duration);

                System.out.println("***********************\n");
            }

            if (library.equals("BoringSSL") && algo.equals("AES-OFB")) {
                System.out.println("***********BoringSSL/AES-OFB**************");



                    BoringSSL test = new BoringSSL();
                    test.AESOFBTime(blocksize,key_duration,sec_duration);




                System.out.println("***********************\n");
            }

            if (library.equals("BoringSSL") && algo.equals("MD5")) {
                System.out.println("***********OpenSSL/MD5**************");


                BoringSSL test = new BoringSSL();
                test.MD5Time(blocksize,sec_duration);


                System.out.println("***********************\n");
            }

            if (library.equals("BoringSSL") && algo.equals("DH")) {
                System.out.println("***********BoringSSL/DH**************");


                    BoringSSL test = new BoringSSL();
                    test.DHTime(key_duration,sec_duration);


                System.out.println("***********************\n");

            }

            if (library.equals("BoringSSL") && algo.equals("ECDH")) {
                System.out.println("***********BoringSSL/ECDH**************");


                    BoringSSL test = new BoringSSL();
                    test.ECDHTime(time_key,sec_duration);

                System.out.println("***********************\n");

            }

            if (library.equals("OpenSSL") && algo.equals("RSA")) {
                System.out.println("***********OpenSSL/RSA**************");



                OpenSSL test = new OpenSSL();
                test.RSATime(128,key_duration,sec_duration);


                System.out.println("***********************\n");
            }

            if (library.equals("OpenSSL") && algo.equals("AES-CBC")) {
                System.out.println("***********OpenSSL/AES-CBC**************");


                    OpenSSL test = new OpenSSL();
                    test.AESCBCTime(blocksize,key_duration,sec_duration);


                System.out.println("***********************\n");
            }

            if (library.equals("OpenSSL") && algo.equals("AES-CTR")) {
                System.out.println("***********OpenSSL/AES-CTR**************");


                    OpenSSL test = new OpenSSL();
                    test.AESCTRTime(blocksize,key_duration,sec_duration);


                System.out.println("***********************\n");
            }

            if (library.equals("OpenSSL") && algo.equals("AES-GCM")) {
                System.out.println("***********OpenSSL/AES-GCM**************");

                    OpenSSL test = new OpenSSL();
                    test.AESGCMTime(blocksize,key_duration,sec_duration);

                System.out.println("***********************\n");
            }

            if (library.equals("OpenSSL") && algo.equals("AES-OFB")) {
                System.out.println("***********OpenSSL/AES-OFB**************");


                    OpenSSL test = new OpenSSL();
                    test.AESOFBTime(blocksize,key_duration,sec_duration);


                System.out.println("***********************\n");
            }

            if (library.equals("OpenSSL") && algo.equals("MD5")) {
                System.out.println("***********OpenSSL/MD5**************");


                    OpenSSL test = new OpenSSL();
                    test.MD5Time(blocksize,sec_duration);


                System.out.println("***********************\n");
            }

            if (library.equals("OpenSSL") && algo.equals("DH")) {
                System.out.println("***********OpenSSL/DH**************");


                    OpenSSL test = new OpenSSL();
                    test.DHTime(key_duration,sec_duration);



                System.out.println("Times executed:" + algo_repet + "\n");

                System.out.println("***********************\n");
            }

            if (library.equals("OpenSSL") && algo.equals("ECDH")) {
                System.out.println("***********OpenSSL/DH**************");

                    OpenSSL test = new OpenSSL();
                    test.ECDHTime(key_duration,sec_duration);


                System.out.println("***********************\n");
            }

            if (library.equals("mbedTLS") && algo.equals("RSA")) {
                System.out.println("***********mbedTLS/RSA**************");


                    mbedTLS test = new mbedTLS();
                    test.RSATime(128,key_duration,sec_duration);


                System.out.println("***********************\n");

            }


            if (library.equals("mbedTLS") && algo.equals("AES-CBC")) {


                    mbedTLS test = new mbedTLS();
                    test.AESCBCTime(blocksize,key_duration,sec_duration);


                System.out.println("***********************\n");
            }

            if (library.equals("mbedTLS") && algo.equals("AES-CTR")) {
                System.out.println("***********mbedTLS/AES**************");

                    mbedTLS test = new mbedTLS();

                    test.AESCTRTime(blocksize,key_duration,sec_duration);



                System.out.println("***********************\n");
            }

            if (library.equals("mbedTLS") && algo.equals("AES-GCM")) {
                System.out.println("***********mbedTLS/AES-GCM**************");

                    mbedTLS test = new mbedTLS();

                    test.AESGCMTime(blocksize,key_duration,sec_duration);


                System.out.println("***********************\n");
            }

            if (library.equals("mbedTLS") && algo.equals("MD5")) {
                System.out.println("***********mbedTLS/MD5**************");

                    mbedTLS test = new mbedTLS();
                    test.MD5Time(blocksize,sec_duration);


                System.out.println("***********************\n");
            }

            if (library.equals("mbedTLS") && algo.equals("ECDH")) {
                System.out.println("***********mbedTLS/ECDH**************");

                    mbedTLS test = new mbedTLS();
                    test.ECDHTime(key_duration, sec_duration);

                System.out.println("***********************\n");
            }

            if (library.equals("mbedTLS") && algo.equals("DH")) {
                System.out.println("***********mbedTLS/DH**************");


                    mbedTLS test = new mbedTLS();
                    test.DHTime(key_duration,sec_duration);


                System.out.println("***********************\n");
            }

            if (library.equals("WolfCrypt") && algo.equals("RSA")) {
                System.out.println("************WolfCrypt/RSA**************");

                    WolfCrypt test = new WolfCrypt();
                    test.RSATime(128,key_duration,sec_duration);

                System.out.println("Times executed:" + algo_repet + "\n");

                System.out.println("********************************");
            }



            if (library.equals("WolfCrypt") && algo.equals("AES-CBC")) {
                System.out.println("************WolfCrypt/AES-CBC**************");

                    WolfCrypt test = new WolfCrypt();
                    test.AESCBCTime(blocksize,key_duration,sec_duration);

                System.out.println("********************************");
            }

            if (library.equals("WolfCrypt") && algo.equals("AES-GCM")) {
                System.out.println("************WolfCrypt/AES-GCM**************");

                    WolfCrypt test = new WolfCrypt();
                    test.AESGCMTime(blocksize,key_duration,sec_duration);

                System.out.println("********************************");
            }

            if (library.equals("WolfCrypt") && algo.equals("AES-CTR")) {
                System.out.println("************WolfCrypt/AES-CTR**************");


                    WolfCrypt test = new WolfCrypt();
                    test.AESCTRTime(blocksize,key_duration,sec_duration);


                System.out.println("********************************");
            }

            if (library.equals("WolfCrypt") && algo.equals("MD5")) {
                System.out.println("************WolfCrypt/MD5**************");


                    WolfCrypt test = new WolfCrypt();
                    test.MD5Time(blocksize,sec_duration);


                System.out.println("********************************");
            }

            if (library.equals("WolfCrypt") && algo.equals("DH")) {

                System.out.println("************WolfCrypt/DH**************");
                    WolfCrypt test = new WolfCrypt();
                    test.DHTime(key_duration,sec_duration);

                System.out.println("********************************");
            }

            if (library.equals("WolfCrypt") && algo.equals("ECDH")) {
                System.out.println("************WolfCrypt/ECDH**************");

                    WolfCrypt test = new WolfCrypt();
                    test.ECDHTime(sec_duration,key_duration);


                System.out.println("Times executed:" + algo_repet + "\n");

                System.out.println("********************************");
            }

        }catch (IOException i){
            throw new RuntimeException(i);
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
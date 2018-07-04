package com.example.CryptoBench.sac;

import android.app.ProgressDialog;
import android.os.AsyncTask;
import android.os.Build;
import android.widget.TextView;

import com.snatik.storage.Storage;

import java.io.FileWriter;
import java.io.IOException;
import java.util.Calendar;
import java.util.Date;
import java.util.Timer;
import java.util.TimerTask;


class TimeTestParams {
    String library;
    String algo;
    int blocksize;
    int time;
    int time_key;
    TextView results;
    FileWriter writer_special;
    FileWriter writer_temp;
    ConcreteTest test;
    Storage storage;
    String title;
    int total_rep;
    int id;

    TimeTestParams(FileWriter writer,FileWriter writer_temp, Storage storage, ConcreteTest test, TextView results, int time, int time_key, String library, String algo, int blocksize,String title,int total_rep,int id) {

        this.writer_special = writer;
        this.storage = storage;
        this.library = library;
        this.algo = algo;
        this.blocksize = blocksize;
        this.time = time;
        this.results = results;
        this.time_key = time_key;
        this.test = test;
        this.writer_temp = writer_temp;
        this.title = title;
        this.total_rep = total_rep;
        this.id = id;

    }
}

//Apparently all these classes should be only one, but it seems to have problems
//changing the values of global variables. Fix this if I have Time
class setTimer extends TimerTask{

    private final int id;
    FileWriter writer_temp;

    setTimer(int id,FileWriter writer_temp){
        this.id = id;
        this.writer_temp = writer_temp;
    }

    @Override
    public void run() {
        System.out.println("Timer started");
        OpenSSL timer_open = new OpenSSL();
        int ret_value = timer_open.setTimer();
        CpuTemp gettemp = new CpuTemp();
        gettemp.getCpuTemp(id,writer_temp);
    }
}

class setTimerBoring extends TimerTask{

    private final int id;
    FileWriter writer_temp;

    setTimerBoring(int id,FileWriter writer_temp){
        this.id = id;
        this.writer_temp = writer_temp;
    }

    @Override
    public void run() {
        System.out.println("Timer started");
        BoringSSL timer_open = new BoringSSL();
        int ret_value = timer_open.setTimer();
        CpuTemp gettemp = new CpuTemp();
        gettemp.getCpuTemp(id,writer_temp);
    }
}

class setTimermbedTLS extends TimerTask{

    private final int id;
    FileWriter writer_temp;

    setTimermbedTLS(int id,FileWriter writer_temp){
        this.id = id;
        this.writer_temp = writer_temp;
    }

    @Override
    public void run() {
        System.out.println("Timer started");
        mbedTLS timer_open = new mbedTLS();
        int ret_value = timer_open.setTimer();
        CpuTemp gettemp = new CpuTemp();
        gettemp.getCpuTemp(id,writer_temp);
    }
}

class setTimerWolfCrypt extends TimerTask{

    private final int id;
    FileWriter writer_temp;

    setTimerWolfCrypt(int id,FileWriter writer_temp){
        this.id = id;
        this.writer_temp = writer_temp;
    }

    @Override
    public void run() {
        System.out.println("Timer started");
        WolfCrypt timer_open = new WolfCrypt();
        int ret_value = timer_open.setTimer();
        CpuTemp gettemp = new CpuTemp();
        gettemp.getCpuTemp(id,writer_temp);
    }
}

class setTimerBC extends TimerTask{

    private final int id;
    FileWriter writer_temp;

    setTimerBC(int id,FileWriter writer_temp){
        this.id = id;
        this.writer_temp = writer_temp;
    }

    @Override
    public void run() {
        System.out.println("Value changed");
        bool_value.value = false;
        CpuTemp gettemp = new CpuTemp();
        gettemp.getCpuTemp(id,writer_temp);
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



        Timer timer = new Timer();

        FileWriter writer = params[0].writer_special;
        final FileWriter writer_temp = params[0].writer_temp;

        TextView results = params[0].results;
        int time = params[0].time;
        int blocksize = params[0].blocksize;
        String algo = params[0].algo;
        String library = params[0].library;
        int time_key = params[0].time_key;
        Storage storage = params[0].storage;
        String title = params[0].title;
        int total_rep = params[0].total_rep;
        int id = params[0].id;


        ConcreteTest context = params[0].test;

        long startTime = System.currentTimeMillis();

        long maxDurationInMilliseconds = time * 60 * 1000;

        int sec_duration = ((int) maxDurationInMilliseconds / 1000);

        long keymaxDurationInMilliseconds = time_key * 60 * 1000;

        long time_for_timer = keymaxDurationInMilliseconds + maxDurationInMilliseconds + 500;

        int key_duration = ((int) keymaxDurationInMilliseconds / 1000) ;

        long resulttime = startTime + maxDurationInMilliseconds;
        int algo_repet = 0;
        try {

            String myVersion = android.os.Build.VERSION.RELEASE;
            int sdkVersion = android.os.Build.VERSION.SDK_INT;
            String manufacturer = Build.MANUFACTURER;
            String device = Build.DEVICE;
            String model = Build.MODEL;

            final String model_cpu = System.getProperty("os.arch");
            Date currentTime = Calendar.getInstance().getTime();

            writer.write("Special Test Results\n");
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

            writer_temp.write("Special Test Temperature  Results\n");
            writer_temp.write("-----------------------------------\n");
            writer_temp.write("CPU Model: " + model_cpu + "\n");
            writer_temp.write("Android Version: " + myVersion + "\n");
            writer_temp.write("SDK Version: " + sdkVersion + "\n");
            writer_temp.write("Manufacturer: " + manufacturer + "\n");
            writer_temp.write("Device: " + device + "\n");
            writer_temp.write("Model: " + model + "\n");
            writer_temp.write("Hour of test " + currentTime + "\n");
            writer_temp.write("\n");
            writer_temp.write("\n");
            writer_temp.write("\n");

            CpuTemp getTemp = new CpuTemp();
            writer_temp.write("Start : ");
            getTemp.getCpuTemp(id,writer_temp);


            if (library.equals("Bouncy Castle") && algo.equals("RSA")) {
                RSA test = new RSA();
                try {
                    System.out.println("************Bouncy Castle/RSA**************");
                    writer.write("\n************Bouncy Castle/RSA***************\n");

                    timer = new Timer();
                    timer.schedule(new setTimerBC(id,writer_temp),time_for_timer,maxDurationInMilliseconds);
                    test.testRSATime(writer, results, 128,keymaxDurationInMilliseconds,maxDurationInMilliseconds,total_rep);

                    System.out.println("********************************");
                    writer.write("********************************\n");
                } catch (Exception i) {
                    throw new RuntimeException(i);
                }
            }


            if (library.equals("Bouncy Castle") && algo.equals("AES-CBC")) {
                AESCBC test = new AESCBC();
                try {
                    System.out.println("************Bouncy Castle/AES-CBC**************");
                    writer.write("\n************Bouncy Castle/AES-CBC***************\n");

                    timer = new Timer();
                    timer.schedule(new setTimerBC(id,writer_temp),time_for_timer,maxDurationInMilliseconds);
                    test.testCBCTime(writer, results, blocksize,keymaxDurationInMilliseconds,maxDurationInMilliseconds,total_rep);

                    System.out.println("********************************");
                    writer.write("********************************\n");
                } catch (Exception i) {
                    throw new RuntimeException(i);
                }
            }

            if (library.equals("Bouncy Castle") && algo.equals("AES-CTR")) {

                System.out.println("************Bouncy Castle/AES-CTR**************");
                writer.write("\n************Bouncy Castle/AES-CTR***************\n");

                    AESCTR test = new AESCTR();
                    try {
                        timer = new Timer();
                        timer.schedule(new setTimerBC(id,writer_temp),time_for_timer,maxDurationInMilliseconds);
                        test.testCTRTime(writer, results, blocksize,keymaxDurationInMilliseconds,maxDurationInMilliseconds,total_rep);
                    } catch (Exception i) {
                        throw new RuntimeException(i);
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
                        timer = new Timer();
                        timer.schedule(new setTimerBC(id,writer_temp),time_for_timer,maxDurationInMilliseconds);
                        test.testGCMTime(writer, results, blocksize,keymaxDurationInMilliseconds,maxDurationInMilliseconds,total_rep);
                    } catch (Exception i) {
                        throw new RuntimeException(i);
                    }
                }

                System.out.println("********************************");
                writer.write("********************************\n");

            }

            if (library.equals("Bouncy Castle") && algo.equals("AES-OFB")) {

                System.out.println("************Bouncy Castle/AES-OFB**************");
                writer.write("\n************Bouncy Castle/AES-OFB***************\n");

                while (System.currentTimeMillis() < startTime + maxDurationInMilliseconds) {
                    AESOFB test = new AESOFB();
                    try {
                        timer = new Timer();
                        timer.schedule(new setTimerBC(id,writer_temp),time_for_timer,maxDurationInMilliseconds);
                        test.testOFBTime(writer, results, blocksize,keymaxDurationInMilliseconds,maxDurationInMilliseconds,total_rep);
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
                        timer = new Timer();
                        timer.schedule(new setTimerBC(id,writer_temp),maxDurationInMilliseconds + 100,maxDurationInMilliseconds);
                        test.testmd5Time(writer, results, maxDurationInMilliseconds,blocksize, total_rep);
                    } catch (Exception i) {
                        throw new RuntimeException(i);
                    }
                }
            }

            if (library.equals("Bouncy Castle") && algo.equals("DH")) {
                while (System.currentTimeMillis() < startTime + maxDurationInMilliseconds) {
                    DiffieHellman test = new DiffieHellman();
                    try {
                        timer = new Timer();
                        timer.schedule(new setTimerBC(id,writer_temp),time_for_timer,maxDurationInMilliseconds);
                        test.testDHTime(writer, results,keymaxDurationInMilliseconds,maxDurationInMilliseconds,total_rep);
                    } catch (Exception i) {
                        throw new RuntimeException(i);
                    }
                }
            }

            if (library.equals("Bouncy Castle") && algo.equals("ECDH")) {
                while (System.currentTimeMillis() < startTime + maxDurationInMilliseconds) {
                    ECDiffieHellmanImplementation test = new ECDiffieHellmanImplementation();
                    try {
                        timer = new Timer();
                        timer.schedule(new setTimerBC(id,writer_temp),time_for_timer,maxDurationInMilliseconds);
                        test.startDiffieHellmanTime(writer, results,keymaxDurationInMilliseconds,maxDurationInMilliseconds,total_rep);
                    } catch (Exception i) {
                        throw new RuntimeException(i);
                    }
                }
            }




            if (library.equals("BoringSSL") && algo.equals("RSA")) {
                System.out.println("***********BoringSSL/RSA**************");


                timer = new Timer();
                BoringSSL test = new BoringSSL();
                timer.schedule(new setTimerBoring(id,writer_temp),time_for_timer,maxDurationInMilliseconds);
                    test.RSATime(128,key_duration,sec_duration,title,total_rep);


                System.out.println("***********************\n");
            }

            if (library.equals("BoringSSL") && algo.equals("AES-CBC")) {
                System.out.println("***********BoringSSL/AES-CBC**************");


                timer = new Timer();
                BoringSSL test = new BoringSSL();
                timer.schedule(new setTimerBoring(id,writer_temp),time_for_timer,maxDurationInMilliseconds);
                test.AESCBCTime(blocksize,key_duration,sec_duration,title,total_rep);


                System.out.println("***********************\n");
            }

            if (library.equals("BoringSSL") && algo.equals("AES-CTR")) {
                System.out.println("***********BoringSSL/AES-CTR**************");

                timer = new Timer();
                BoringSSL test = new BoringSSL();
                timer.schedule(new setTimerBoring(id,writer_temp),time_for_timer,maxDurationInMilliseconds);
                    test.AESCTRTime(blocksize,key_duration,sec_duration,title,total_rep);

                System.out.println("***********************\n");
            }

            if (library.equals("BoringSSL") && algo.equals("AES-GCM")) {
                System.out.println("***********BoringSSL/AES-GCM**************");

                timer = new Timer();
                BoringSSL test = new BoringSSL();
                timer.schedule(new setTimerBoring(id,writer_temp),time_for_timer,maxDurationInMilliseconds);
                    test.AESGCMTime(blocksize,key_duration,sec_duration,title,total_rep);

                System.out.println("***********************\n");
            }

            if (library.equals("BoringSSL") && algo.equals("AES-OFB")) {
                System.out.println("***********BoringSSL/AES-OFB**************");



                timer = new Timer();
                BoringSSL test = new BoringSSL();
                timer.schedule(new setTimerBoring(id,writer_temp),time_for_timer,maxDurationInMilliseconds);
                    test.AESOFBTime(blocksize,key_duration,sec_duration,title,total_rep);




                System.out.println("***********************\n");
            }

            if (library.equals("BoringSSL") && algo.equals("MD5")) {
                System.out.println("***********OpenSSL/MD5**************");


                timer = new Timer();
                BoringSSL test = new BoringSSL();
                timer.schedule(new setTimerBoring(id,writer_temp),maxDurationInMilliseconds,maxDurationInMilliseconds + 200);
                test.MD5Time(blocksize,sec_duration,title,total_rep);


                System.out.println("***********************\n");
            }

            if (library.equals("BoringSSL") && algo.equals("DH")) {
                System.out.println("***********BoringSSL/DH**************");


                timer = new Timer();
                BoringSSL test = new BoringSSL();
                timer.schedule(new setTimerBoring(id,writer_temp),time_for_timer,maxDurationInMilliseconds);
                    test.DHTime(key_duration,sec_duration,title,total_rep);


                System.out.println("***********************\n");

            }

            if (library.equals("BoringSSL") && algo.equals("ECDH")) {
                System.out.println("***********BoringSSL/ECDH**************");


                timer = new Timer();
                BoringSSL test = new BoringSSL();
                timer.schedule(new setTimerBoring(id,writer_temp),time_for_timer,maxDurationInMilliseconds);
                    test.ECDHTime(time_key,sec_duration,title,total_rep);

                System.out.println("***********************\n");

            }

            if (library.equals("OpenSSL") && algo.equals("RSA")) {
                System.out.println("***********OpenSSL/RSA**************");

                timer = new Timer();
                OpenSSL test = new OpenSSL();
                timer.schedule(new setTimer(id,writer_temp),time_for_timer,maxDurationInMilliseconds);
                test.RSATime(128,key_duration,sec_duration,title,total_rep);


                System.out.println("***********************\n");
            }

            if (library.equals("OpenSSL") && algo.equals("AES-CBC")) {
                System.out.println("***********OpenSSL/AES-CBC**************");


                timer = new Timer();
                OpenSSL test = new OpenSSL();
                timer.schedule(new setTimer(id,writer_temp),time_for_timer,maxDurationInMilliseconds);
                    test.AESCBCTime(blocksize,key_duration,sec_duration,title,total_rep);


                System.out.println("***********************\n");
            }

            if (library.equals("OpenSSL") && algo.equals("AES-CTR")) {
                System.out.println("***********OpenSSL/AES-CTR**************");


                timer = new Timer();
                OpenSSL test = new OpenSSL();
                timer.schedule(new setTimer(id,writer_temp),time_for_timer,maxDurationInMilliseconds);
                    test.AESCTRTime(blocksize,key_duration,sec_duration,title,total_rep);


                System.out.println("***********************\n");
            }

            if (library.equals("OpenSSL") && algo.equals("AES-GCM")) {
                System.out.println("***********OpenSSL/AES-GCM**************");

                timer = new Timer();
                OpenSSL test = new OpenSSL();
                timer.schedule(new setTimer(id,writer_temp),time_for_timer,maxDurationInMilliseconds);
                    test.AESGCMTime(blocksize,key_duration,sec_duration,title,total_rep);

                System.out.println("***********************\n");
            }

            if (library.equals("OpenSSL") && algo.equals("AES-OFB")) {
                System.out.println("***********OpenSSL/AES-OFB**************");


                    timer = new Timer();
                    OpenSSL test = new OpenSSL();
                    timer.schedule(new setTimer(id,writer_temp),time_for_timer,maxDurationInMilliseconds);
                    test.AESOFBTime(blocksize,key_duration,sec_duration,title,total_rep);


                System.out.println("***********************\n");
            }

            if (library.equals("OpenSSL") && algo.equals("MD5")) {
                System.out.println("***********OpenSSL/MD5**************");


                    timer = new Timer();
                    OpenSSL test = new OpenSSL();
                    timer.schedule(new setTimer(id,writer_temp),maxDurationInMilliseconds + 100,maxDurationInMilliseconds);
                    test.MD5Time(blocksize,sec_duration,title,total_rep);


                System.out.println("***********************\n");
            }

            if (library.equals("OpenSSL") && algo.equals("DH")) {
                System.out.println("***********OpenSSL/DH**************");


                    timer = new Timer();
                    OpenSSL test = new OpenSSL();
                    timer.schedule(new setTimer(id,writer_temp),time_for_timer,maxDurationInMilliseconds);
                    test.DHTime(key_duration,sec_duration,title,total_rep);



                System.out.println("Times executed:" + algo_repet + "\n");

                System.out.println("***********************\n");
            }

            if (library.equals("OpenSSL") && algo.equals("ECDH")) {
                System.out.println("***********OpenSSL/DH**************");

                    timer = new Timer();
                    OpenSSL test = new OpenSSL();
                    timer.schedule(new setTimer(id,writer_temp),time_for_timer,maxDurationInMilliseconds);
                    test.ECDHTime(key_duration,sec_duration,title,total_rep);


                System.out.println("***********************\n");
            }

            if (library.equals("mbedTLS") && algo.equals("RSA")) {
                System.out.println("***********mbedTLS/RSA**************");

                    timer = new Timer();
                    mbedTLS test = new mbedTLS();
                    timer.schedule(new setTimermbedTLS(id,writer_temp),time_for_timer,maxDurationInMilliseconds);
                    test.RSATime(128,key_duration,sec_duration,title,total_rep);


                System.out.println("***********************\n");

            }


            if (library.equals("mbedTLS") && algo.equals("AES-CBC")) {

                timer = new Timer();
                mbedTLS test = new mbedTLS();
                timer.schedule(new setTimermbedTLS(id,writer_temp),time_for_timer,maxDurationInMilliseconds);
                    test.AESCBCTime(blocksize,key_duration,sec_duration,title,total_rep);


                System.out.println("***********************\n");
            }

            if (library.equals("mbedTLS") && algo.equals("AES-CTR")) {
                System.out.println("***********mbedTLS/AES**************");

                timer = new Timer();
                mbedTLS test = new mbedTLS();
                timer.schedule(new setTimermbedTLS(id,writer_temp),time_for_timer,maxDurationInMilliseconds);

                    test.AESCTRTime(blocksize,key_duration,sec_duration,title,total_rep);



                System.out.println("***********************\n");
            }

            if (library.equals("mbedTLS") && algo.equals("AES-GCM")) {
                System.out.println("***********mbedTLS/AES-GCM**************");

                timer = new Timer();
                mbedTLS test = new mbedTLS();
                timer.schedule(new setTimermbedTLS(id,writer_temp),time_for_timer,maxDurationInMilliseconds);

                    test.AESGCMTime(blocksize,key_duration,sec_duration,title,total_rep);


                System.out.println("***********************\n");
            }

            if (library.equals("mbedTLS") && algo.equals("MD5")) {
                System.out.println("***********mbedTLS/MD5**************");

                timer = new Timer();
                mbedTLS test = new mbedTLS();
                timer.schedule(new setTimermbedTLS(id,writer_temp),maxDurationInMilliseconds + 100,maxDurationInMilliseconds);
                    test.MD5Time(blocksize,sec_duration,title,total_rep);


                System.out.println("***********************\n");
            }

            if (library.equals("mbedTLS") && algo.equals("ECDH")) {
                System.out.println("***********mbedTLS/ECDH**************");

                    timer = new Timer();
                mbedTLS test = new mbedTLS();
                timer.schedule(new setTimermbedTLS(id,writer_temp),time_for_timer,maxDurationInMilliseconds);
                    test.ECDHTime(key_duration, sec_duration,title,total_rep);

                System.out.println("***********************\n");
            }

            if (library.equals("mbedTLS") && algo.equals("DH")) {
                System.out.println("***********mbedTLS/DH**************");


                timer = new Timer();
                mbedTLS test = new mbedTLS();
                timer.schedule(new setTimermbedTLS(id,writer_temp),time_for_timer,maxDurationInMilliseconds);
                    test.DHTime(key_duration,sec_duration,title,total_rep);


                System.out.println("***********************\n");
            }

            if (library.equals("WolfCrypt") && algo.equals("RSA")) {
                System.out.println("************WolfCrypt/RSA**************");

                timer = new Timer();
                WolfCrypt test = new WolfCrypt();
                timer.schedule(new setTimerWolfCrypt(id,writer_temp),time_for_timer,maxDurationInMilliseconds);
                    test.RSATime(128,key_duration,sec_duration,title,total_rep);

                System.out.println("Times executed:" + algo_repet + "\n");

                System.out.println("********************************");
            }



            if (library.equals("WolfCrypt") && algo.equals("AES-CBC")) {
                System.out.println("************WolfCrypt/AES-CBC**************");

                timer = new Timer();
                WolfCrypt test = new WolfCrypt();
                timer.schedule(new setTimerWolfCrypt(id,writer_temp),time_for_timer,maxDurationInMilliseconds);
                    test.AESCBCTime(blocksize,key_duration,sec_duration,title,total_rep);

                System.out.println("********************************");
            }

            if (library.equals("WolfCrypt") && algo.equals("AES-GCM")) {
                System.out.println("************WolfCrypt/AES-GCM**************");

                timer = new Timer();
                WolfCrypt test = new WolfCrypt();
                timer.schedule(new setTimerWolfCrypt(id,writer_temp),time_for_timer,maxDurationInMilliseconds);
                    test.AESGCMTime(blocksize,key_duration,sec_duration,title,total_rep);

                System.out.println("********************************");
            }

            if (library.equals("WolfCrypt") && algo.equals("AES-CTR")) {
                System.out.println("************WolfCrypt/AES-CTR**************");


                timer = new Timer();
                WolfCrypt test = new WolfCrypt();
                timer.schedule(new setTimerWolfCrypt(id,writer_temp),time_for_timer,maxDurationInMilliseconds);
                    test.AESCTRTime(blocksize,key_duration,sec_duration,title,total_rep);


                System.out.println("********************************");
            }

            if (library.equals("WolfCrypt") && algo.equals("MD5")) {
                System.out.println("************WolfCrypt/MD5**************");


                timer = new Timer();
                WolfCrypt test = new WolfCrypt();
                timer.schedule(new setTimerWolfCrypt(id,writer_temp),maxDurationInMilliseconds,maxDurationInMilliseconds);
                    test.MD5Time(blocksize,sec_duration,title,total_rep);


                System.out.println("********************************");
            }

            if (library.equals("WolfCrypt") && algo.equals("DH")) {

                System.out.println("************WolfCrypt/DH**************");
                timer = new Timer();
                WolfCrypt test = new WolfCrypt();
                timer.schedule(new setTimerWolfCrypt(id,writer_temp),time_for_timer,maxDurationInMilliseconds);
                    test.DHTime(key_duration,sec_duration,title,total_rep);

                System.out.println("********************************");
            }

            if (library.equals("WolfCrypt") && algo.equals("ECDH")) {
                System.out.println("************WolfCrypt/ECDH**************");
                timer = new Timer();
                WolfCrypt test = new WolfCrypt();
                timer.schedule(new setTimerWolfCrypt(id,writer_temp),time_for_timer,maxDurationInMilliseconds);
                    test.ECDHTime(sec_duration,key_duration,title,total_rep);


                System.out.println("********************************");
            }
            timer.cancel();
        }catch (IOException i){
            throw new RuntimeException(i);
        }
        return results;
    }

    @Override
    protected void onPostExecute(final TextView report) {
        dialog.dismiss();
        report.setText("\n"+ "Test finished successfully"+"\n"+"\n"+"  Find your results at " +
                "CryptoBench/");
        super.onPostExecute(report);
    }


}
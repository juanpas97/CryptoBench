package com.example.juanperezdealgaba.sac;

import android.content.Context;
import android.os.AsyncTask;
import android.util.Log;
import android.widget.TextView;

import java.io.FileWriter;

class WolfCryptParamsTest {
    String randomString;
    FileWriter writer;
    TextView results;
    Context  context;
    int repetitions;

    WolfCryptParamsTest(String randomString, FileWriter writer, TextView results, Context context, int repetitions) {
        this.randomString = randomString;
        this.writer = writer;
        this.results = results;
        this.context = context;
        this.repetitions = repetitions;
    }
}

public class AsyncWolfCrypt extends AsyncTask<WolfCryptParamsTest,Void,String> {

    @Override
    protected String doInBackground(WolfCryptParamsTest... paramsTests) {
        String randomString = paramsTests[0].randomString;
        FileWriter writer = paramsTests[0].writer;
        TextView results = paramsTests[0].results;
        Context context = paramsTests[0].context;
        int repetitions = paramsTests[0].repetitions;

        StringBuilder text = new StringBuilder();
        String finalString;

        try {


            System.out.println("***********WolfCrypt**************");
            writer.write("**********WolfCrypt***************\n");
            text.append("**********WolfCrypt************\n");

            WolfCrypt test = new WolfCrypt();

            System.out.println("***********AES-CBC**************");
            writer.write("**********AES-CBC***************\n");
            text.append("**********AES-CBC************\n");

            for(int i = 0; i < repetitions; i++) {
                int[] timesAES = test.AESCBC(64);

                System.out.println("Time to encrypt:" + timesAES[0] + "ms\n");
                writer.write("Time to encrypt:" + timesAES[0] + "ms\n");
                text.append("Time to encrypt:" + timesAES[0] + "ms\n");


                System.out.println("Time to decrypt:" + timesAES[1] + "ms\n");
                writer.write("Time to decrypt:" + timesAES[1] + "ms\n");
                text.append("Time to decrypt:" + timesAES[1] + "ms\n");
                text.append("\n");
            }
            System.out.println("***********************\n");
            writer.write("********************************\n");
            text.append("**********************************\n");

            System.out.println("***********AES-CTR**************");
            writer.write("**********AES-CTR***************\n");
            text.append("**********AES-CTR************\n");

            for(int i = 0; i < repetitions; i++) {
                int[] timesAES = test.AESCTR(64);

                System.out.println("Time to encrypt:" + timesAES[0] + "ns\n");
                writer.write("Time to encrypt:" + timesAES[0] + "ns\n");
                text.append("Time to encrypt:" + timesAES[0] + "ns\n");


                System.out.println("Time to decrypt:" + timesAES[1] + "ns\n");
                writer.write("Time to decrypt:" + timesAES[1] + "ns\n");
                text.append("Time to decrypt:" + timesAES[1] + "ns\n");
                text.append("\n");
            }
            System.out.println("***********************\n");
            writer.write("********************************\n");
            text.append("**********************************\n");

            System.out.println("***********AES-GCM**************");
            writer.write("**********AES-GCM***************\n");
            text.append("**********AES-GCM************\n");

            for(int i = 0; i < repetitions; i++) {
                int[] timesAES = test.AESGCM(64);

                System.out.println("Time to encrypt:" + timesAES[0] + "ns\n");
                writer.write("Time to encrypt:" + timesAES[0] + "ns\n");
                text.append("Time to encrypt:" + timesAES[0] + "ns\n");


                System.out.println("Time to decrypt:" + timesAES[1] + "ns\n");
                writer.write("Time to decrypt:" + timesAES[1] + "ns\n");
                text.append("Time to decrypt:" + timesAES[1] + "ns\n");
                text.append("\n");
            }
            System.out.println("***********************\n");
            writer.write("********************************\n");
            text.append("**********************************\n");

            System.out.println("***********DH**************");
            writer.write("**********DH***************\n");
            text.append("**********DH************\n");


            for (int i = 0; i < repetitions; i++) {
                int[] testDH = test.DH();
                System.out.println("Time to key agreement:" + testDH[1] + "ns\n");
                writer.write("Time to key agreement:" + testDH[1] + "ns\n");
                text.append("Time to key agreement:" + testDH[1] + "ns\n");
                text.append("\n");
            }

            System.out.println("***********************\n");
            writer.write("********************************\n");
            text.append("**********************************\n");

            System.out.println("***********MD5**************");
            writer.write("**********MD5***************\n");
            text.append("**********MD5************\n");

            for (int i = 0; i < repetitions; i++) {
                int[] testMD5 = test.MD5(64);
                System.out.println("Time to generate hash:" + testMD5[1] + "ns\n");
                writer.write("Time to generate hash:" + testMD5[1] + "ns\n");
                text.append("Time to generate hash:" + testMD5[1] + "ns\n");
                text.append("\n");
            }

            System.out.println("***********************\n");
            writer.write("********************************\n");
            text.append("**********************************\n");

        } catch (Exception i) {
            Log.e("Test", i.getMessage(), i);
        }

        finalString = text.toString();
        return finalString;
    }

    @Override
    protected void onPostExecute(String finalString) {

        super.onPostExecute(finalString);
    }
}

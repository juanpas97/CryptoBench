package com.example.juanperezdealgaba.sac;

import android.content.Context;
import android.os.AsyncTask;
import android.util.Log;
import android.widget.TextView;

import java.io.FileWriter;

class BoringSSLParamsTest {
    String randomString;
    FileWriter writer;
    TextView results;
    Context  context;
    int repetitions;

    BoringSSLParamsTest(String randomString, FileWriter writer, TextView results, Context context, int repetitions) {
        this.randomString = randomString;
        this.writer = writer;
        this.results = results;
        this.context = context;
        this.repetitions = repetitions;
    }
}

public class AsyncBoringSSL extends AsyncTask<BoringSSLParamsTest,Void,String> {

    @Override
    protected String doInBackground(BoringSSLParamsTest... paramsTests) {
        String randomString = paramsTests[0].randomString;
        FileWriter writer = paramsTests[0].writer;
        TextView results = paramsTests[0].results;
        Context context = paramsTests[0].context;
        int repetitions = paramsTests[0].repetitions;

        StringBuilder text = new StringBuilder();
        String finalString;

        try {


            System.out.println("***********BoringSSL**************");
            writer.write("**********BoringSSL***************\n");
            text.append("**********BoringSSL************\n");

            BoringSSL test = new BoringSSL();

            System.out.println("***********RSA**************");
            writer.write("**********RSA***************\n");
            text.append("**********RSA************\n");

            for(int i = 0; i < repetitions; i++) {
                double[] timesRSA = test.RSA();

                System.out.println("Time to encrypt:" + timesRSA[0] + "ns\n");
                writer.write("Time to encrypt:" + timesRSA[0] + "ns\n");
                text.append("Time to encrypt:" + timesRSA[0] + "ns\n");


                System.out.println("Time to decrypt:" + timesRSA[1] + "ns\n");
                writer.write("Time to decrypt:" + timesRSA[1] + "ns\n");
                text.append("Time to decrypt:" + timesRSA[1] + "ns\n");
                text.append("\n");
            }

            System.out.println("***********************\n");
            writer.write("********************************\n");
            text.append("**********************************\n");

            System.out.println("***********AES**************");
            writer.write("**********AES***************\n");
            text.append("**********AES************\n");

            for(int i = 0; i < repetitions; i++) {
                double[] timesAES = test.AES();

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
                double[] testDH = test.DH();
                System.out.println("Time to key agreement:" + testDH[1] + "ns\n");
                writer.write("Time to key agreement:" + testDH[1] + "ns\n");
                text.append("Time to key agreement:" + testDH[1] + "ns\n");
                text.append("\n");
            }

            System.out.println("***********************\n");
            writer.write("********************************\n");
            text.append("**********************************\n");

            writer.close();
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

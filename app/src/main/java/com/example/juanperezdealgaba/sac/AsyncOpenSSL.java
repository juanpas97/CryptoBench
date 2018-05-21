package com.example.juanperezdealgaba.sac;

import android.content.Context;
import android.os.AsyncTask;
import android.util.Log;
import android.widget.TextView;

import java.io.FileWriter;

class OpenSSLParamsTest {
    String randomString;
    FileWriter writer;
    TextView results;
    Context  context;
    int repetitions;

    OpenSSLParamsTest(String randomString, FileWriter writer, TextView results, Context context, int repetitions) {
        this.randomString = randomString;
        this.writer = writer;
        this.results = results;
        this.context = context;
        this.repetitions = repetitions;
    }
}

public class AsyncOpenSSL extends AsyncTask<OpenSSLParamsTest,Void,String> {

    @Override
    protected String doInBackground(OpenSSLParamsTest... paramsTests) {
        String randomString = paramsTests[0].randomString;
        FileWriter writer = paramsTests[0].writer;
        TextView results = paramsTests[0].results;
        Context context = paramsTests[0].context;
        int repetitions = paramsTests[0].repetitions;

        StringBuilder text = new StringBuilder();
        String finalString;

        try {


            System.out.println("***********OpenSSL**************");
            writer.write("**********OpenSSL***************\n");
            text.append("**********OpenSSL************\n");

            OpenSSL test = new OpenSSL();

            System.out.println("***********AES**************");
            writer.write("**********AES***************\n");
            text.append("**********AES************\n");

            for(int i = 0; i < repetitions; i++) {
                double[] timesAES = test.AES(3);

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


            System.out.println("***********RSA**************");
            writer.write("**********RSA***************\n");
            text.append("**********RSA************\n");

            for(int i = 0; i < repetitions; i++) {
                double[] timesRSA = test.RSA(3);

                System.out.println("Time to encrypt:" + timesRSA[0] + "ns\n");
                writer.write("Time to encrypt:" + timesRSA[0] + "ns\n");
                text.append("Time to encrypt:" + timesRSA[0] + "ns\n");


                System.out.println("Time to decrypt:" + timesRSA[1] + "ns\n");
                writer.write("Time to decrypt:" + timesRSA[1] + "ns\n");
                text.append("Time to decrypt:" + timesRSA[1] + "ns\n");
                text.append("\n");
            }

            System.out.println("***********MD5**************");
            writer.write("**********MD5***************\n");
            text.append("**********MD5************\n");

                for (int i = 0; i < repetitions; i++) {
                    double[] testMD5 = test.MD5();
                    System.out.println("Time to generate hash:" + testMD5[1] + "ns\n");
                    writer.write("Time to generate hash:" + testMD5[1] + "ns\n");
                    text.append("Time to generate hash:" + testMD5[1] + "ns\n");
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

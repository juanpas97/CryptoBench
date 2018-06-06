package com.example.juanperezdealgaba.sac;

import android.content.Context;
import android.os.AsyncTask;
import android.util.Log;
import android.widget.TextView;

import java.io.FileWriter;

class MbedTLSParamsTest {
    String randomString;
    FileWriter writer;
    TextView results;
    Context  context;
    int repetitions;

   MbedTLSParamsTest(String randomString, FileWriter writer, TextView results, Context context, int repetitions) {
        this.randomString = randomString;
        this.writer = writer;
        this.results = results;
        this.context = context;
        this.repetitions = repetitions;
    }
}

public class AsyncMbedTLS extends AsyncTask<MbedTLSParamsTest,Void,String> {

    @Override
    protected String doInBackground(MbedTLSParamsTest... paramsTests) {
        String randomString = paramsTests[0].randomString;
        FileWriter writer = paramsTests[0].writer;
        TextView results = paramsTests[0].results;
        Context context = paramsTests[0].context;
        int repetitions = paramsTests[0].repetitions;

        StringBuilder text = new StringBuilder();
        String finalString;

        try {


            System.out.println("***********mbedTLS**************");
            writer.write("**********mbedTLS***************\n");
            text.append("**********mbedTLS************\n");

            mbedTLS test = new mbedTLS();

            System.out.println("***********AES**************");
            writer.write("**********AES***************\n");
            text.append("**********AES************\n");

            for(int i = 0; i < repetitions; i++) {
                int[] timesAES = test.AESCBC(64);

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

            System.out.println("***********MD5**************");
            writer.write("**********MD5***************\n");
            text.append("**********MD5************\n");

            for (int i = 0; i < repetitions; i++) {
                int[] testMD5 = test.MD5();
                System.out.println("Time to generate hash:" + testMD5[1] + "ns\n");
                writer.write("Time to generate hash:" + testMD5[1] + "ns\n");
                text.append("Time to generate hash:" + testMD5[1] + "ns\n");
                text.append("\n");
            }

            System.out.println("***********************\n");
            writer.write("********************************\n");
            text.append("**********************************\n");

            System.out.println("***********RSA**************");
            writer.write("**********RSA***************\n");
            text.append("**********RSA************\n");

            for(int i = 0; i < repetitions; i++) {
                int[] timesRSA = test.RSA();

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

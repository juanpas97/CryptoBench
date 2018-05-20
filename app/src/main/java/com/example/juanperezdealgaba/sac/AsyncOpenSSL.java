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

public class AsyncOpenSSL extends AsyncTask<OpenSSLParamsTest,Void,TextView> {

    @Override
    protected TextView doInBackground(OpenSSLParamsTest... paramsTests) {
        String randomString = paramsTests[0].randomString;
        FileWriter writer = paramsTests[0].writer;
        TextView results = paramsTests[0].results;
        Context context = paramsTests[0].context;
        int repetitions = paramsTests[0].repetitions;

        try {

            System.out.println("***********OpenSSL**************");
            writer.write("**********OpenSSL***************\n");
            results.append("**********OpenSSL************\n");

            OpenSSL test = new OpenSSL();

            System.out.println("***********AES**************");
            writer.write("**********AES***************\n");
            results.append("**********AES************\n");

            for(int i = 0; i < repetitions; i++) {
                double[] timesAES = test.AES(3);

                System.out.println("Time to encrypt:" + timesAES[0] + "ns\n");
                writer.write("Time to encrypt:" + timesAES[0] + "ns\n");
                results.append("Time to encrypt:" + timesAES[0] + "ns\n");


                System.out.println("Time to decrypt:" + timesAES[1] + "ns\n");
                writer.write("Time to decrypt:" + timesAES[1] + "ns\n");
                results.append("Time to decrypt:" + timesAES[1] + "ns\n");
                results.append("\n");
            }

            System.out.println("***********************\n");
            writer.write("********************************\n");
            results.append("**********************************\n");


            System.out.println("***********RSA**************");
            writer.write("**********RSA***************\n");
            results.append("**********RSA************\n");

            for(int i = 0; i < repetitions; i++) {
                double[] timesRSA = test.RSA(3);

                System.out.println("Time to encrypt:" + timesRSA[0] + "ns\n");
                writer.write("Time to encrypt:" + timesRSA[0] + "ns\n");
                results.append("Time to encrypt:" + timesRSA[0] + "ns\n");


                System.out.println("Time to decrypt:" + timesRSA[1] + "ns\n");
                writer.write("Time to decrypt:" + timesRSA[1] + "ns\n");
                results.append("Time to decrypt:" + timesRSA[1] + "ns\n");
                results.append("\n");
            }

            System.out.println("***********MD5**************");
            writer.write("**********MD5***************\n");
            results.append("**********MD5************\n");


                test.MD5();
                //System.out.println("Time to generate hash:" + timesMD5[0] + "ns\n");
                //writer.write("Time to generate hash:" + timesMD5[0] + "ns\n");
                //results.append("Time to generate hash:" + timesMD5[0] + "ns\n");
                results.append("\n");


            System.out.println("***********************\n");
            writer.write("********************************\n");
            results.append("**********************************\n");
            writer.close();

        } catch (Exception i) {
            Log.e("Test", i.getMessage(), i);
        }
        return results;
    }
}

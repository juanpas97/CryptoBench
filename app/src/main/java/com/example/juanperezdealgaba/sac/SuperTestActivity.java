package com.example.juanperezdealgaba.sac;

import android.os.AsyncTask;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.text.method.ScrollingMovementMethod;
import android.util.Log;
import android.widget.TextView;

import com.snatik.storage.Storage;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.concurrent.ExecutionException;

public class SuperTestActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_super_test);

        try{
            //Initialize SuperTest
            final TextView results = (TextView) findViewById(R.id.Results);
            results.setMovementMethod(new ScrollingMovementMethod());

            String input = RandomStringGenerator.generateRandomString();
            Storage storage = new Storage(getApplicationContext());

            String path = storage.getExternalStorageDirectory();

            final String newDir = path + File.separator + "Encryptapp";

            final File report = new File(newDir, "Report.txt");
            report.mkdirs();

            if (report.exists())
                report.delete();

            FileWriter writer = new FileWriter(report);


            //mbedTLS prueba = new mbedTLS();

            //prueba.AES();

            //prueba.RSA();

            //prueba.DH();

            //prueba.AES();


            int repetitions = 5;


            MyTaskParamsTest paramsTest = new MyTaskParamsTest(input,writer,results,SuperTestActivity.this, repetitions);
            AsyncTest superTest = new AsyncTest();

            superTest.execute(paramsTest);


            MyTaskParams params = new MyTaskParams(input, writer, results,repetitions);
            AsyncRSA myTask = new AsyncRSA();

            myTask.execute(params);

            OpenSSLParamsTest prueba = new OpenSSLParamsTest(input,writer,results,SuperTestActivity.this,repetitions);
            AsyncOpenSSL Open = new AsyncOpenSSL();

            String texttoappend = Open.execute(prueba).get();

            results.append(texttoappend);

            BoringSSLParamsTest boringsslparams = new BoringSSLParamsTest(input,writer,results,SuperTestActivity.this,repetitions);
            AsyncBoringSSL Open_boring = new AsyncBoringSSL();

            String boringresults = Open_boring.execute(boringsslparams).get();
            results.append(boringresults);

            WolfCryptParamsTest wolfcryptparams = new WolfCryptParamsTest(input,writer,results,SuperTestActivity.this,repetitions);
            AsyncWolfCrypt Open_wolfcrypt = new AsyncWolfCrypt();

            String wolfcryptresults = Open_wolfcrypt.execute(wolfcryptparams).get();
            results.append(wolfcryptresults);

            MbedTLSParamsTest mbedparams = new MbedTLSParamsTest(input,writer,results,SuperTestActivity.this,repetitions);
            AsyncMbedTLS Open_mbed = new AsyncMbedTLS();

            String mbedresults = Open_mbed.execute(mbedparams).get();
            results.append(mbedresults);


            writer.close();

            //AlertDialog alertTest = builder1.create();
            //alertTest.show();

            final String model_cpu = System.getProperty("os.arch");
            final GMailSender sender = new GMailSender("encryptapp.report@gmail.com",
                    "EncryptAppReport");
            new AsyncTask<Void, Void, Void>() {
                @Override
                public Void doInBackground(Void... arg) {
                    try {
                        sender.sendMail("Report",
                                model_cpu,
                                "encryptapp.report@gmail.com",
                                "encryptapp.report@gmail.com",
                                report);
                    } catch (Exception e) {
                        Log.e("SendMail", e.getMessage(), e);
                    }
                    return null;
                }
            }.execute();

        }catch(IOException i){
            throw new RuntimeException(i);
        }catch (InterruptedException o){
            throw new RuntimeException(o);
        }catch (ExecutionException u){
            throw new RuntimeException(u);
        }
    }
}

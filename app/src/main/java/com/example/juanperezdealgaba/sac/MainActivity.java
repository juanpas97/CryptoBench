package com.example.juanperezdealgaba.sac;

import android.Manifest;

import android.annotation.SuppressLint;
import android.app.AlertDialog;

import android.content.DialogInterface;
import android.content.pm.PackageManager;

import android.os.AsyncTask;

import android.support.annotation.NonNull;
import android.support.v4.app.ActivityCompat;
import android.support.v4.content.ContextCompat;
import android.support.v7.app.AppCompatActivity;

import android.os.Bundle;

import android.text.method.ScrollingMovementMethod;
import android.util.Log;

import android.view.View;

import android.widget.Button;

import android.content.Context;
import android.widget.TextView;
import android.widget.Toast;

import com.afollestad.materialdialogs.MaterialDialog;
import com.snatik.storage.Storage;


import java.io.File;

import java.io.FileWriter;
import java.io.IOException;



public  class  MainActivity extends AppCompatActivity {



    // Used to load the 'native-lib' library on application startup.
    static {
        System.loadLibrary("native-lib");
    }

    private static final int REQUEST_WRITE_STORAGE = 112;
    private Storage mStorage;
    Context context = this;


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        final Context context = this;



        final MaterialDialog.Builder builder = new MaterialDialog.Builder(MainActivity.this)
                .title(R.string.Executing_tests)
                .content(R.string.please_wait)
                .progress(true, 0);



        /**
        * Used to create the folder
        */

        mStorage = new Storage(getApplicationContext());



        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        /**
        * We check permissions during runtime because of API > 23
        */

        boolean hasPermission = (ContextCompat.checkSelfPermission(MainActivity.this,
                Manifest.permission.WRITE_EXTERNAL_STORAGE) == PackageManager.PERMISSION_GRANTED);
        if (!hasPermission) {
            ActivityCompat.requestPermissions(MainActivity.this,
                    new String[]{Manifest.permission.WRITE_EXTERNAL_STORAGE},
                    REQUEST_WRITE_STORAGE);
        }



        /**
        * When the App is initialized for first time, we will create the Encryptapp
        * in "external" storage
        */

        Storage storage = new Storage(getApplicationContext());

        String path = storage.getExternalStorageDirectory();

        final String newDir = path + File.separator + "Encryptapp";
        storage.createDirectory(newDir);


        // Example of a call to a native method
        //TextView tv = (TextView) findViewById(R.id.sample_text);
        //tv.setText(stringFromJNI());


        /**
        * Super test is the main function of the Application. The report and the
        * execution times will be messed here.
        */

        final Button Benchmark = findViewById(R.id.SuperTest);
        Benchmark.setOnClickListener(new View.OnClickListener() {

            @SuppressLint("StaticFieldLeak")
            public void onClick(View v) {

                MaterialDialog dialog = builder.build();
                dialog.show();

        try{
                //Initialize SuperTest
                final TextView results = (TextView) findViewById(R.id.Results);
                results.setMovementMethod(new ScrollingMovementMethod());

                String input = RandomStringGenerator.generateRandomString();
                Storage storage = new Storage(context);

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


                MyTaskParamsTest paramsTest = new MyTaskParamsTest(input,writer,results,MainActivity.this, repetitions);
                AsyncTest superTest = new AsyncTest();

                superTest.execute(paramsTest);


                MyTaskParams params = new MyTaskParams(input, writer, results,repetitions);
                AsyncRSA myTask = new AsyncRSA();

                myTask.execute(params);



                //Show Alert
                AlertDialog.Builder builder1 = new AlertDialog.Builder(context);
                builder1.setMessage("Test finished successfully!");
                builder1.setCancelable(true);

                builder1.setPositiveButton(
                        "Accept",
                        new DialogInterface.OnClickListener() {
                            public void onClick(DialogInterface dialog, int id) {
                                dialog.cancel();
                            }
                        });

                builder1.setNegativeButton(
                        "Cancel",
                        new DialogInterface.OnClickListener() {
                            public void onClick(DialogInterface dialog, int id) {
                                dialog.cancel();
                            }
                        });

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
                dialog.dismiss();

            }catch(IOException i){
                    throw new RuntimeException(i);
                }

            }
        });

    }

    /**
     * A native method that is implemented by the 'native-lib' native library,
     * which is packaged with this app.
     */

    //public native String stringFromJNI();



    /**
     * Standard function that executes the function when the user has
     * the necessary permissions.
     */



    @Override
    public void onRequestPermissionsResult(int requestCode, String[] permissions,@NonNull int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        switch (requestCode) {
            case REQUEST_WRITE_STORAGE: {
                if (grantResults.length > 0 && grantResults[0] == PackageManager.PERMISSION_GRANTED) {

                } else {
                    Toast.makeText(this, "The app was not allowed to write to your storage. " +
                            "Hence, it cannot function properly. Please consider granting it this permission", Toast.LENGTH_LONG).show();
                }
            }


        }


    }


}

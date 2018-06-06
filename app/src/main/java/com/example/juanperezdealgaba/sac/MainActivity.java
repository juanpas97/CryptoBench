package com.example.juanperezdealgaba.sac;

import android.Manifest;

import android.annotation.SuppressLint;

import android.content.Intent;
import android.content.pm.PackageManager;



import android.support.annotation.NonNull;
import android.support.v4.app.ActivityCompat;
import android.support.v4.content.ContextCompat;
import android.support.v7.app.AppCompatActivity;

import android.os.Bundle;


import android.view.View;

import android.widget.Button;

import android.content.Context;

import android.widget.Toast;

import com.afollestad.materialdialogs.MaterialDialog;
import com.snatik.storage.Storage;


import java.io.File;

import java.io.FileWriter;
import java.io.IOException;
import java.util.concurrent.ExecutionException;

import static android.provider.AlarmClock.EXTRA_MESSAGE;


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

        final String newDir = path + File.separator + "CryptoBench";
        storage.createDirectory(newDir);

        final File report_public = new File(newDir, "public_key.txt");
        report_public.mkdirs();
        final File report_private = new File(newDir, "private_key.txt");
        if (report_public.exists())
            report_public.delete();
        if (report_private.exists())
            report_private.delete();

        try {
            FileWriter writer = new FileWriter(report_public);
            writer.append("-----BEGIN PUBLIC KEY-----\n" +
                    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAy8Dbv8prpJ/0kKhlGeJY\n" +
                    "ozo2t60EG8L0561g13R29LvMR5hyvGZlGJpmn65+A4xHXInJYiPuKzrKUnApeLZ+\n" +
                    "vw1HocOAZtWK0z3r26uA8kQYOKX9Qt/DbCdvsF9wF8gRK0ptx9M6R13NvBxvVQAp\n" +
                    "fc9jB9nTzphOgM4JiEYvlV8FLhg9yZovMYd6Wwf3aoXK891VQxTr/kQYoq1Yp+68\n" +
                    "i6T4nNq7NWC+UNVjQHxNQMQMzU6lWCX8zyg3yH88OAQkUXIXKfQ+NkvYQ1cxaMoV\n" +
                    "PpY72+eVthKzpMeyHkBn7ciumk5qgLTEJAfWZpe4f4eFZj/Rc8Y8Jj2IS5kVPjUy\n" +
                    "wQIDAQAB\n" +
                    "-----END PUBLIC KEY-----");
            writer.close();

        }catch(IOException i) {
            throw new RuntimeException(i);
        }

        try{
            FileWriter writer_priv = new FileWriter(report_private);
            writer_priv.append("-----BEGIN RSA PRIVATE KEY-----\n"+
                    "MIIEowIBAAKCAQEAy8Dbv8prpJ/0kKhlGeJYozo2t60EG8L0561g13R29LvMR5hy\n" +
                    "vGZlGJpmn65+A4xHXInJYiPuKzrKUnApeLZ+vw1HocOAZtWK0z3r26uA8kQYOKX9\n"+
                    "Qt/DbCdvsF9wF8gRK0ptx9M6R13NvBxvVQApfc9jB9nTzphOgM4JiEYvlV8FLhg9\n"+
                    "yZovMYd6Wwf3aoXK891VQxTr/kQYoq1Yp+68i6T4nNq7NWC+UNVjQHxNQMQMzU6l\n"+
                    "WCX8zyg3yH88OAQkUXIXKfQ+NkvYQ1cxaMoVPpY72+eVthKzpMeyHkBn7ciumk5q\n"+
                    "gLTEJAfWZpe4f4eFZj/Rc8Y8Jj2IS5kVPjUywQIDAQABAoIBADhg1u1Mv1hAAlX8\n"+
                    "omz1Gn2f4AAW2aos2cM5UDCNw1SYmj+9SRIkaxjRsE/C4o9sw1oxrg1/z6kajV0e\n"+
                    "N/t008FdlVKHXAIYWF93JMoVvIpMmT8jft6AN/y3NMpivgt2inmmEJZYNioFJKZG\n"+
                    "X+/vKYvsVISZm2fw8NfnKvAQK55yu+GRWBZGOeS9K+LbYvOwcrjKhHz66m4bedKd\n"+
                    "gVAix6NE5iwmjNXktSQlJMCjbtdNXg/xo1/G4kG2p/MO1HLcKfe1N5FgBiXj3Qjl\n"+
                    "vgvjJZkh1as2KTgaPOBqZaP03738VnYg23ISyvfT/teArVGtxrmFP7939EvJFKpF\n"+
                    "1wTxuDkCgYEA7t0DR37zt+dEJy+5vm7zSmN97VenwQJFWMiulkHGa0yU3lLasxxu\n"+
                    "m0oUtndIjenIvSx6t3Y+agK2F3EPbb0AZ5wZ1p1IXs4vktgeQwSSBdqcM8LZFDvZ\n"+
                    "uPboQnJoRdIkd62XnP5ekIEIBAfOp8v2wFpSfE7nNH2u4CpAXNSF9HsCgYEA2l8D\n"+
                    "JrDE5m9Kkn+J4l+AdGfeBL1igPF3DnuPoV67BpgiaAgI4h25UJzXiDKKoa706S0D\n"+
                    "4XB74zOLX11MaGPMIdhlG+SgeQfNoC5lE4ZWXNyESJH1SVgRGT9nBC2vtL6bxCVV\n"+
                    "WBkTeC5D6c/QXcai6yw6OYyNNdp0uznKURe1xvMCgYBVYYcEjWqMuAvyferFGV+5\n"+
                    "nWqr5gM+yJMFM2bEqupD/HHSLoeiMm2O8KIKvwSeRYzNohKTdZ7FwgZYxr8fGMoG\n"+
                    "PxQ1VK9DxCvZL4tRpVaU5Rmknud9hg9DQG6xIbgIDR+f79sb8QjYWmcFGc1SyWOA\n"+
                    "SkjlykZ2yt4xnqi3BfiD9QKBgGqLgRYXmXp1QoVIBRaWUi55nzHg1XbkWZqPXvz1\n"+
                    "I3uMLv1jLjJlHk3euKqTPmC05HoApKwSHeA0/gOBmg404xyAYJTDcCidTg6hlF96\n"+
                    "ZBja3xApZuxqM62F6dV4FQqzFX0WWhWp5n301N33r0qR6FumMKJzmVJ1TA8tmzEF\n"+
                    "yINRAoGBAJqioYs8rK6eXzA8ywYLjqTLu/yQSLBn/4ta36K8DyCoLNlNxSuox+A5\n"+
                    "w6z2vEfRVQDq4Hm4vBzjdi3QfYLNkTiTqLcvgWZ+eX44ogXtdTDO7c+GeMKWz4XX\n"+
                    "uJSUVL5+CVjKLjZEJ6Qc2WZLl94xSwL71E41H4YciVnSCQxVc4Jw\n"+
                    "-----END RSA PRIVATE KEY-----\n");
            writer_priv.close();
        }catch(IOException e){
            throw new RuntimeException(e);
        }

        // Example of a call to a native method
        //TextView tv = (TextView) findViewById(R.id.sample_text);
        //tv.setText(stringFromJNI());

        final Button special_test = findViewById(R.id.button_special_test);

        special_test.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                Intent specialtest = new Intent(view.getContext(), ConcreteTest.class);
                String message = "Special Test";
                specialtest.putExtra(EXTRA_MESSAGE, message);
                startActivity(specialtest);
            }
        });

        /**
        * Super test is the main function of the Application. The report and the
        * execution times will be messed here.
        */

        final Button Benchmark = findViewById(R.id.SuperTest);
        Benchmark.setOnClickListener(new View.OnClickListener() {

            @SuppressLint("StaticFieldLeak")
            public void onClick(View v) {

                Intent supertest = new Intent(v.getContext(), SuperTestActivity.class);
                String message = "SuperTest";
                supertest.putExtra(EXTRA_MESSAGE, message);
                startActivity(supertest);

            }
        });

        final Button completeTest = findViewById(R.id.complete_test);
        completeTest.setOnClickListener(new View.OnClickListener() {

            @SuppressLint("StaticFieldLeak")
            public void onClick(View v) {

                Intent complete = new Intent(v.getContext(), CompleteTestActivity.class);

                startActivity(complete);

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

package com.example.juanperezdealgaba.sac;

import android.Manifest;

import android.annotation.SuppressLint;
import android.app.AlertDialog;

import android.content.DialogInterface;
import android.content.Intent;
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
import android.widget.EditText;
import android.widget.TextView;
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

        final String newDir = path + File.separator + "Encryptapp";
        storage.createDirectory(newDir);


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

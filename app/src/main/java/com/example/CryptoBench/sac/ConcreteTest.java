package com.example.CryptoBench.sac;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.graphics.Color;
import android.os.AsyncTask;
import android.os.BatteryManager;
import android.os.Build;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.text.method.ScrollingMovementMethod;
import android.util.Log;
import android.view.View;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Spinner;
import android.widget.TextView;

import com.snatik.storage.Storage;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;


public class ConcreteTest extends AppCompatActivity implements AdapterView.OnItemSelectedListener{

    public static String library;
    public static String algo;


    @Override
    protected void onCreate(Bundle savedInstanceState) {


            super.onCreate(savedInstanceState);
            setContentView(R.layout.activity_concrete_test);

            final TextView results_special_test = findViewById(R.id.special_test_results);

            final EditText minutes_repetition = findViewById(R.id.minutes_text);

            final EditText blocksize_value = findViewById(R.id.blocksize_text);

            final EditText key_value = findViewById(R.id.key_text);

            final EditText rep_value = findViewById(R.id.rep_text);

            results_special_test.setMovementMethod(new ScrollingMovementMethod());

        final int[] repetitions = new int[1];
        final int[] blocksize = new int[1];
        final int[] key_time = new int[1];
        final int[] rep_total = new int[1];
        final Global global = new Global();

        final Storage storage = new Storage(getApplicationContext());

        Intent intent = getIntent();
        Bundle extras = intent.getExtras();

        if ( extras != null ) {

            int key_rep;
            for (String key : extras.keySet()) {
                System.out.println("BEFORE BUNDLE");
                Object value = extras.get(key);
                Log.d("BUNDLE", String.format("%s %s (%s)", key,
                        value.toString(), value.getClass().getName()));
            }

            if ( extras.containsKey ( "lib" ) ) {
                System.out.println("We started shell");
                String rep = extras.getString ( "lib" );
                if(rep.equals("Bouncy")){
                    library = "Bouncy Castle";
                }
                else {
                    library = rep;
                }
            }

            if ( extras.containsKey ( "algo" ) ) {
                System.out.println("AES SHELL");
                String rep = extras.getString ( "algo" );
                algo = rep;
            } else {
                algo = "RSA";
            }

            if ( extras.containsKey ( "min" ) ) {
                String rep =extras.getString ( "min" );
                repetitions[0] = Integer.parseInt(rep);
            } else {
                repetitions[0] = 1;
            }

            if ( extras.containsKey ( "blocksize" ) ) {
                String rep =extras.getString ( "blocksize" );
                blocksize[0] = Integer.parseInt(rep);
            } else {
                blocksize[0] = 1024;
            }

            if ( extras.containsKey ( "key" ) ) {
                String rep =extras.getString ( "key" );
                key_rep = Integer.parseInt(rep);
            } else {
                key_rep = 1;
            }

            if ( extras.containsKey ( "rep" ) ) {
                String rep = extras.getString ( "rep" );
                rep_total[0] = Integer.parseInt(rep);
            } else {
                rep_total[0] = 1;
            }

            System.out.println("Shell function");

            RandomStringGenerator rand = new RandomStringGenerator();
            String title = rand.generateRandomString(5);
            System.out.println("the random string is : " + title);
            try {
                String path = storage.getExternalStorageDirectory();
                final String newDir = path + File.separator + "CryptoBench";
                final File report_special = new File(newDir, "Special_test_" + title + ".txt");
                report_special.mkdirs();

                if (report_special.exists())
                    report_special.delete();


                final File report_temperature = new File(newDir, "temperature_" + title + ".txt");
                report_temperature.mkdirs();

                if (report_temperature.exists())
                    report_temperature.delete();

                final FileWriter writer_special = new FileWriter(report_special);
                global.writer_temp = new FileWriter(report_temperature);

                int id = 0;
                String model = Build.MODEL;

                //If I have time later, change this condition for a general array with all the phones
                if(model.equals("XT1572") || model.equals("One X")){
                    id = 1;
                }

                ConcreteTest context = ConcreteTest.this;
                TimeTestParams TimeParamsTest = new TimeTestParams(writer_special, global.writer_temp, storage, context, results_special_test, repetitions[0], key_rep, library, algo, blocksize[0],title,rep_total[0],id);

                TimeTestAsync test = new TimeTestAsync(ConcreteTest.this);
                test.execute(TimeParamsTest);
            }catch (IOException i){
                throw new RuntimeException(i);
            }
        }
                Spinner spinner_algo = findViewById(R.id.spinner_algo);
// Create an ArrayAdapter using the string array and a default spinner layout
                ArrayAdapter<CharSequence> adapter = ArrayAdapter.createFromResource(this,
                        R.array.algo_array, android.R.layout.simple_spinner_item);
// Specify the layout to use when the list of choices appears
                adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
// Apply the adapter to the spinner
                spinner_algo.setAdapter(adapter);

                spinner_algo.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
                    @Override
                    public void onItemSelected(AdapterView<?> adapterView, View view, int i, long l) {

                        algo = adapterView.getItemAtPosition(i).toString();

                        if (algo.equals("RSA")) {
                            System.out.println("RSA");
                        }

                        if (algo.equals("DH")) {
                            System.out.println("DH");
                        }

                        if (algo.equals("MD-5")) {
                            System.out.println("MD-5");
                        }

                        if (algo.equals("AES")) {
                            System.out.println("AES");
                        }
                    }

                    @Override
                    public void onNothingSelected(AdapterView<?> adapterView) {

                    }
                });

                Spinner spinner_library = findViewById(R.id.spinner_library);
// Create an ArrayAdapter using the string array and a default spinner layout
                ArrayAdapter<CharSequence> adapterlibrary = ArrayAdapter.createFromResource(this,
                        R.array.libraries_array, android.R.layout.simple_spinner_item);
// Specify the layout to use when the list of choices appears
                adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
// Apply the adapter to the spinner
                spinner_library.setAdapter(adapterlibrary);

                spinner_library.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
                    @Override
                    public void onItemSelected(AdapterView<?> adapterView, View view, int i, long l) {
                        library = adapterView.getItemAtPosition(i).toString();

                        if (library.equals("Bouncy Castle")) {
                            System.out.println("Bouncy Castle");
                        }

                        if (library.equals("WolfCrypt")) {
                            System.out.println("WolfCrypt");
                        }

                        if (library.equals("mbedTLS")) {
                            System.out.println("mbedTLS");
                        }

                        if (library.equals("OpenSSL")) {
                            System.out.println("OpenSSL");
                        }

                        if (library.equals("BoringSSL")) {
                            System.out.println("BoringSSL");
                        }
                    }

                    @Override
                    public void onNothingSelected(AdapterView<?> adapterView) {

                    }
                });

                final Button start_test = findViewById(R.id.button_special_test);
                start_test.setOnClickListener(new View.OnClickListener() {
                    @Override
                    public void onClick(View view) {
                        results_special_test.setText("");

                        try {

                            RandomStringGenerator rand = new RandomStringGenerator();
                            String title = rand.generateRandomString(5);

                            String path = storage.getExternalStorageDirectory();
                            final String newDir = path + File.separator + "CryptoBench";
                            final File report_special = new File(newDir, "Special_test_"+title+".txt");
                            report_special.mkdirs();

                            if (report_special.exists())
                                report_special.delete();


                            final File report_temperature = new File(newDir, "temperature_" + title + ".txt");
                            report_temperature.mkdirs();

                            if (report_temperature.exists())
                                report_temperature.delete();
                            final FileWriter writer_special = new FileWriter(report_special);
                            global.writer_temp = new FileWriter(report_temperature);
                            if (minutes_repetition.getText().toString().equals("")) {
                                repetitions[0] = 1;
                            }else{
                                repetitions[0] = Integer.parseInt(minutes_repetition.getText().toString());
                            }
                            if (blocksize_value.getText().toString().equals("")) {
                                blocksize[0] = 1024;
                            }else{
                                blocksize[0] = Integer.parseInt(blocksize_value.getText().toString());
                            }
                            if (key_value.getText().toString().equals("")) {
                                key_time[0] = 1;
                            }else{
                                key_time[0] = Integer.parseInt(key_value.getText().toString());
                            }

                            if (rep_value.getText().toString().equals("")) {
                                rep_total[0] = 1;
                            }else{
                                rep_total[0] = Integer.parseInt(rep_value.getText().toString());
                            }

                            int id = 0;
                            String model = Build.MODEL;
                            if(model.equals("XT1572")|| model.equals("One X")){
                                id = 1;
                            }
                            ConcreteTest context = ConcreteTest.this;
                            if (library != null && algo != null && key_time[0] != 0 && blocksize[0] != 0 && repetitions[0] != 0) {
                                    TimeTestParams TimeParamsTest = new TimeTestParams(writer_special, global.writer_temp, storage, context, results_special_test, repetitions[0], key_time[0], library, algo, blocksize[0],title, rep_total[0],id);

                                    TimeTestAsync test = new TimeTestAsync(ConcreteTest.this);
                                    test.execute(TimeParamsTest);
                                }




                        final GMailSender sender = new GMailSender("encryptapp.report@gmail.com",
                                "EncryptAppReport");
                        new AsyncTask<Void, Void, Void>() {
                            @Override
                            public Void doInBackground(Void... arg) {
                                try {
                                    writer_special.close();
                                    global.writer_temp.close();
                                    sender.sendMail("Special_test",
                                            "Special Test",
                                            "encr" +
                                                    "yptapp.report@gmail.com",
                                            "encryptapp.report@gmail.com",
                                            report_special);
                                    System.out.println("E-mail sent");
                                } catch (Exception e) {
                                    Log.e("SendMail", e.getMessage(), e);
                                }
                                return null;
                            }
                        }.execute();

                        new AsyncTask<Void, Void, Void>() {
                            @Override
                            public Void doInBackground(Void... arg) {
                                try {

                                    sender.sendMail("Temperature test",
                                            "Temperature test",
                                            "encr" +
                                                    "yptapp.report@gmail.com",
                                            "encryptapp.report@gmail.com",
                                            report_temperature);
                                    System.out.println("E-mail sent");
                                } catch (Exception e) {
                                    Log.e("SendMail", e.getMessage(), e);
                                }
                                return null;
                            }
                        }.execute();
                        }catch (IOException i){
                            throw new RuntimeException(i);
                        }
                    }
                });


    }


    @Override
    public void onItemSelected(AdapterView<?> adapterView, View view, int i, long l) {
        ((TextView) adapterView.getChildAt(0)).setTextColor(Color.GREEN);
    }

    @Override
    public void onNothingSelected(AdapterView<?> adapterView) {

    }
}


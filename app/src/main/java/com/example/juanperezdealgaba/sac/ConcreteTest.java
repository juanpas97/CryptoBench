package com.example.juanperezdealgaba.sac;

import android.os.AsyncTask;
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

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;


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

            results_special_test.setMovementMethod(new ScrollingMovementMethod());

            Storage storage = new Storage(getApplicationContext());

            String path = storage.getExternalStorageDirectory();



        final String newDir = path + File.separator + "CryptoBench";

        final File report_special = new File(newDir, "Special_test.txt");
        report_special.mkdirs();

        if (report_special.exists())
            report_special.delete();

            try {
                final FileWriter writer_special = new FileWriter(report_special);

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
                        int repetitions = Integer.parseInt(minutes_repetition.getText().toString());
                        int blocksize = Integer.parseInt(blocksize_value.getText().toString());
                        int key_time = Integer.parseInt(key_value.getText().toString());

                        TimeTestParams TimeParamsTest = new TimeTestParams(writer_special, results_special_test,repetitions,key_time, library, algo, blocksize);

                        TimeTestAsync test = new TimeTestAsync(ConcreteTest.this);
                        test.execute(TimeParamsTest);

                        final String titel = System.getProperty("os.arch");
                        final GMailSender sender = new GMailSender("encryptapp.report@gmail.com",
                                "EncryptAppReport");
                        new AsyncTask<Void, Void, Void>() {
                            @Override
                            public Void doInBackground(Void... arg) {
                                try {
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


                    }
                });

            }catch (IOException i){
                throw new RuntimeException(i);
            }

    }

    public void createAlgo (String library, String algo, TextView textview, final File report,int repetitions){



    }

    @Override
    public void onItemSelected(AdapterView<?> adapterView, View view, int i, long l) {

    }

    @Override
    public void onNothingSelected(AdapterView<?> adapterView) {

    }
}


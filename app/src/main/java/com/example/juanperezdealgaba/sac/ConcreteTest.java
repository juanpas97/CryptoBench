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

            results_special_test.setMovementMethod(new ScrollingMovementMethod());

            Storage storage = new Storage(getApplicationContext());

            String path = storage.getExternalStorageDirectory();

            final String newDir = path + File.separator + "Encryptapp";

            final File report = new File(newDir, "Report.txt");
            report.mkdirs();

            if (report.exists())
                report.delete();


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
                    int repetitions = Integer.parseInt(minutes_repetition.getText().toString());
                    createAlgo(library, algo, results_special_test,report,repetitions);
                }
            });



    }

    public void createAlgo (String library, String algo, TextView textview, final File report,int repetitions){

        long startTime = System.currentTimeMillis();
        long maxDurationInMilliseconds = repetitions * 60 * 1000;

        long resulttime = startTime + maxDurationInMilliseconds;
        int algo_repet = 0;


        try {
            final FileWriter writer = new FileWriter(report);
            String myVersion = android.os.Build.VERSION.RELEASE;
            int sdkVersion = android.os.Build.VERSION.SDK_INT;
            String manufacturer = Build.MANUFACTURER;
            String device = Build.DEVICE;
            String model = Build.MODEL;

            final String model_cpu = System.getProperty("os.arch");


            writer.write("Super Test Results\n");
            writer.write("-----------------------------------\n");
            writer.write("CPU Model: " + model_cpu + "\n");
            writer.write("Android Version: " + myVersion + "\n");
            writer.write("SDK Version: " + sdkVersion + "\n");
            writer.write("Manufacturer: " + manufacturer + "\n");
            writer.write("Device: " + device + "\n");
            writer.write("Model: " + model + "\n");
            textview.setText("Super Test Results\n" + "*********************************\n"
                    + "Model CPU: " + model_cpu + "\n" + "Android Version:"+myVersion+"\n"+
                    "SDK Version: "+ sdkVersion + "\n" + "Manufacturer: " + manufacturer + "\n" +
                    "Device: " + device + "\n" + "Model: " + model + "\n"
                    + "********************************\n\n");
            writer.write("\n");
            writer.write("\n");
            writer.write("\n");


            if (library.equals("BoringSSL") && algo.equals("RSA")) {
                System.out.println("***********BoringSSL/RSA**************");
                writer.write("**********BoringSSL/RSA***************\n");
                textview.append("**********BoringSSL/RSA************\n");

                while (System.currentTimeMillis() < startTime + maxDurationInMilliseconds) {
                    BoringSSL test = new BoringSSL();
                    int[] timesRSA = test.RSA();

                    System.out.println("Time to encrypt:" + timesRSA[0] + "ms\n");
                    writer.write("Time to encrypt:" + timesRSA[0] + "ms\n");
                    textview.append("Time to encrypt:" + timesRSA[0] + "ms\n");


                    System.out.println("Time to decrypt:" + timesRSA[1] + "ms\n");
                    writer.write("Time to decrypt:" + timesRSA[1] + "ms\n");
                    textview.append("Time to decrypt:" + timesRSA[1] + "ms\n");
                    textview.append("\n");
                }

                System.out.println("***********************\n");
                writer.write("********************************\n");
                textview.append("**********************************\n");
            }

            if (library.equals("BoringSSL") && algo.equals("AES-CBC")) {
                System.out.println("***********BoringSSL/AES-CBC**************");
                writer.write("**********BoringSSL/AES-CBC***************\n");
                textview.append("**********BoringSSL/AES-CBC************\n");



                while (System.currentTimeMillis() < startTime + maxDurationInMilliseconds){
                    BoringSSL test = new BoringSSL();
                    int[] timesAES = test.AESCBC();

                    System.out.println("Time to encrypt:" + timesAES[0] + "ms\n");
                    writer.write("Time to encrypt:" + timesAES[0] + "ms\n");
                    textview.append("Time to encrypt:" + timesAES[0] + "ms\n");


                    System.out.println("Time to decrypt:" + timesAES[1] + "ms\n");
                    writer.write("Time to decrypt:" + timesAES[1] + "ms\n");
                    textview.append("Time to decrypt:" + timesAES[1] + "ms\n");
                    textview.append("\n");
                    algo_repet += 1;
                }

                System.out.println("Times executed:" + algo_repet + "\n");
                writer.write("Times executed:" + algo_repet + "\n");
                textview.append("Times executed:" + algo_repet + "\n");

                System.out.println("***********************\n");
                writer.write("********************************\n");
                textview.append("**********************************\n");
            }

            if (library.equals("BoringSSL") && algo.equals("AES-CTR")) {
                System.out.println("***********BoringSSL/AES-CTR**************");
                writer.write("**********BoringSSL/AES-CTR***************\n");
                textview.append("**********BoringSSL/AES-CTR************\n");



                while (System.currentTimeMillis() < startTime + maxDurationInMilliseconds){
                    BoringSSL test = new BoringSSL();
                    int[] timesAES = test.AESCTR();

                    System.out.println("Time to encrypt:" + timesAES[0] + "ms\n");
                    writer.write("Time to encrypt:" + timesAES[0] + "ms\n");
                    textview.append("Time to encrypt:" + timesAES[0] + "ms\n");


                    System.out.println("Time to decrypt:" + timesAES[1] + "ms\n");
                    writer.write("Time to decrypt:" + timesAES[1] + "ms\n");
                    textview.append("Time to decrypt:" + timesAES[1] + "ms\n");
                    textview.append("\n");
                    algo_repet += 1;
                }

                System.out.println("Times executed:" + algo_repet + "\n");
                writer.write("Times executed:" + algo_repet + "\n");
                textview.append("Times executed:" + algo_repet + "\n");

                System.out.println("***********************\n");
                writer.write("********************************\n");
                textview.append("**********************************\n");
            }

            if (library.equals("BoringSSL") && algo.equals("AES-GCM")) {
                System.out.println("***********BoringSSL/AES-GCM**************");
                writer.write("**********BoringSSL/AES-GCM***************\n");
                textview.append("**********BoringSSL/AES-GCM************\n");



                while (System.currentTimeMillis() < startTime + maxDurationInMilliseconds){
                    BoringSSL test = new BoringSSL();
                    int[] timesAES = test.AESGCM();

                    System.out.println("Time to encrypt:" + timesAES[0] + "ms\n");
                    writer.write("Time to encrypt:" + timesAES[0] + "ms\n");
                    textview.append("Time to encrypt:" + timesAES[0] + "ms\n");


                    System.out.println("Time to decrypt:" + timesAES[1] + "ms\n");
                    writer.write("Time to decrypt:" + timesAES[1] + "ms\n");
                    textview.append("Time to decrypt:" + timesAES[1] + "ms\n");
                    textview.append("\n");
                    algo_repet += 1;
                }

                System.out.println("Times executed:" + algo_repet + "\n");
                writer.write("Times executed:" + algo_repet + "\n");
                textview.append("Times executed:" + algo_repet + "\n");

                System.out.println("***********************\n");
                writer.write("********************************\n");
                textview.append("**********************************\n");
            }

            if (library.equals("BoringSSL") && algo.equals("AES-OFB")) {
                System.out.println("***********BoringSSL/AES-OFB**************");
                writer.write("**********BoringSSL/AES-OFB***************\n");
                textview.append("**********BoringSSL/AES-OFB************\n");



                while (System.currentTimeMillis() < startTime + maxDurationInMilliseconds){
                    BoringSSL test = new BoringSSL();
                    int[] timesAES = test.AESOFB();

                    System.out.println("Time to encrypt:" + timesAES[0] + "ms\n");
                    writer.write("Time to encrypt:" + timesAES[0] + "ms\n");
                    textview.append("Time to encrypt:" + timesAES[0] + "ms\n");


                    System.out.println("Time to decrypt:" + timesAES[1] + "ms\n");
                    writer.write("Time to decrypt:" + timesAES[1] + "ms\n");
                    textview.append("Time to decrypt:" + timesAES[1] + "ms\n");
                    textview.append("\n");
                    algo_repet += 1;
                }

                System.out.println("Times executed:" + algo_repet + "\n");
                writer.write("Times executed:" + algo_repet + "\n");
                textview.append("Times executed:" + algo_repet + "\n");

                System.out.println("***********************\n");
                writer.write("********************************\n");
                textview.append("**********************************\n");
            }

            if (library.equals("BoringSSL") && algo.equals("MD5")) {
                System.out.println("***********BoringSSL/MD5**************");
                writer.write("**********BoringSSL/MD5***************\n");
                textview.append("**********BoringSSL/MD5************\n");

                while (System.currentTimeMillis() < startTime + maxDurationInMilliseconds) {
                    BoringSSL test = new BoringSSL();
                    int[] testMD5 = test.MD5();
                    System.out.println("Time to generate hash:" + testMD5[1] + "ms\n");
                    writer.write("Time to generate hash:" + testMD5[1] + "ms\n");
                    textview.append("Time to generate hash:" + testMD5[1] + "ms\n");
                    textview.append("\n");
                    algo_repet += 1;
                }

                System.out.println("Times executed:" + algo_repet + "\n");
                writer.write("Times executed:" + algo_repet + "\n");
                textview.append("Times executed:" + algo_repet + "\n");

                System.out.println("***********************\n");
                writer.write("********************************\n");
                textview.append("**********************************\n");
            }

            if (library.equals("BoringSSL") && algo.equals("DH")) {
                System.out.println("***********BoringSSL/DH**************");
                writer.write("**********BoringSSL/DH***************\n");
                textview.append("**********BoringSSL/DH************\n");


                while (System.currentTimeMillis() < startTime + maxDurationInMilliseconds) {
                BoringSSL test = new BoringSSL();
                int[] testDH = test.DH();
                System.out.println("Time to key agreement:" + testDH[1] + "ms\n");
                writer.write("Time to key agreement:" + testDH[1] + "ms\n");
                textview.append("Time to key agreement:" + testDH[1] + "ms\n");
                textview.append("\n");
                    algo_repet += 1;
                }

                System.out.println("Times executed:" + algo_repet + "\n");
                writer.write("Times executed:" + algo_repet + "\n");
                textview.append("Times executed:" + algo_repet + "\n");


                System.out.println("***********************\n");
                writer.write("********************************\n");
                textview.append("**********************************\n");

            }

            if (library.equals("BoringSSL") && algo.equals("ECDH")) {
                System.out.println("***********BoringSSL/ECDH**************");
                writer.write("**********BoringSSL/ECDH***************\n");
                textview.append("**********BoringSSL/ECDH************\n");


                while (System.currentTimeMillis() < startTime + maxDurationInMilliseconds) {
                    OpenSSL test = new OpenSSL();
                    int[] testDH = test.ECDH();
                    System.out.println("Time to key agreement:" + testDH[1] + "ms\n");
                    writer.write("Time to key agreement:" + testDH[1] + "ms\n");
                    textview.append("Time to key agreement:" + testDH[1] + "ms\n");
                    textview.append("\n");
                    algo_repet += 1;
                }

                System.out.println("Times executed:" + algo_repet + "\n");
                writer.write("Times executed:" + algo_repet + "\n");
                textview.append("Times executed:" + algo_repet + "\n");


                System.out.println("***********************\n");
                writer.write("********************************\n");
                textview.append("**********************************\n");

            }

            if (library.equals("OpenSSL") && algo.equals("RSA")) {
                System.out.println("***********OpenSSL/RSA**************");
                writer.write("**********OpenSSL/RSA***************\n");
                textview.append("**********OpenSSL/RSA************\n");

                while (System.currentTimeMillis() < startTime + maxDurationInMilliseconds) {
                    OpenSSL test = new OpenSSL();
                    int[] timesRSA = test.RSA(3);

                    System.out.println("Time to encrypt:" + timesRSA[0] + "ns\n");
                    writer.write("Time to encrypt:" + timesRSA[0] + "ns\n");
                    textview.append("Time to encrypt:" + timesRSA[0] + "ns\n");


                    System.out.println("Time to decrypt:" + timesRSA[1] + "ns\n");
                    writer.write("Time to decrypt:" + timesRSA[1] + "ns\n");
                    textview.append("Time to decrypt:" + timesRSA[1] + "ns\n");
                    textview.append("\n");
                    algo_repet += 1;
                }

                System.out.println("Times executed:" + algo_repet + "\n");
                writer.write("Times executed:" + algo_repet + "\n");
                textview.append("Times executed:" + algo_repet + "\n");

                System.out.println("***********************\n");
                writer.write("********************************\n");
                textview.append("**********************************\n");
            }

            if (library.equals("OpenSSL") && algo.equals("AES-CBC")) {
                System.out.println("***********OpenSSL/AES-CBC**************");
                writer.write("**********OpenSSL/AES-CBC***************\n");
                textview.append("**********OpenSSL/AES-CBC************\n");

                while (System.currentTimeMillis() < startTime + maxDurationInMilliseconds) {
                    OpenSSL test = new OpenSSL();
                    int[] timesAES = test.AESCBC(3);

                    System.out.println("Time to encrypt:" + timesAES[0] + "ms\n");
                    writer.write("Time to encrypt:" + timesAES[0] + "ms\n");
                    textview.append("Time to encrypt:" + timesAES[0] + "ms\n");


                    System.out.println("Time to decrypt:" + timesAES[1] + "ms\n");
                    writer.write("Time to decrypt:" + timesAES[1] + "ms\n");
                    textview.append("Time to decrypt:" + timesAES[1] + "ms\n");
                    textview.append("\n");
                    algo_repet += 1;
                }

                System.out.println("Times executed:" + algo_repet + "\n");
                writer.write("Times executed:" + algo_repet + "\n");
                textview.append("Times executed:" + algo_repet + "\n");

                System.out.println("***********************\n");
                writer.write("********************************\n");
                textview.append("**********************************\n");
            }

            if (library.equals("OpenSSL") && algo.equals("AES-CTR")) {
                System.out.println("***********OpenSSL/AES-CTR**************");
                writer.write("**********OpenSSL/AES-CTR***************\n");
                textview.append("**********OpenSSL/AES-CTR************\n");

                while (System.currentTimeMillis() < startTime + maxDurationInMilliseconds) {
                    OpenSSL test = new OpenSSL();
                    int[] timesAES = test.AESCTR();

                    System.out.println("Time to encrypt:" + timesAES[0] + "ms\n");
                    writer.write("Time to encrypt:" + timesAES[0] + "ms\n");
                    textview.append("Time to encrypt:" + timesAES[0] + "ms\n");


                    System.out.println("Time to decrypt:" + timesAES[1] + "ms\n");
                    writer.write("Time to decrypt:" + timesAES[1] + "ms\n");
                    textview.append("Time to decrypt:" + timesAES[1] + "ms\n");
                    textview.append("\n");
                    algo_repet += 1;
                }

                System.out.println("Times executed:" + algo_repet + "\n");
                writer.write("Times executed:" + algo_repet + "\n");
                textview.append("Times executed:" + algo_repet + "\n");

                System.out.println("***********************\n");
                writer.write("********************************\n");
                textview.append("**********************************\n");
            }

            if (library.equals("OpenSSL") && algo.equals("AES-GCM")) {
                System.out.println("***********OpenSSL/AES-GCM**************");
                writer.write("**********OpenSSL/AES-GCM***************\n");
                textview.append("**********OpenSSL/AES-GCM************\n");

                while (System.currentTimeMillis() < startTime + maxDurationInMilliseconds) {
                    OpenSSL test = new OpenSSL();
                    int[] timesAES = test.AESGCM();

                    System.out.println("Time to encrypt:" + timesAES[0] + "ms\n");
                    writer.write("Time to encrypt:" + timesAES[0] + "ms\n");
                    textview.append("Time to encrypt:" + timesAES[0] + "ms\n");


                    System.out.println("Time to decrypt:" + timesAES[1] + "ms\n");
                    writer.write("Time to decrypt:" + timesAES[1] + "ms\n");
                    textview.append("Time to decrypt:" + timesAES[1] + "ms\n");
                    textview.append("\n");
                    algo_repet += 1;
                }

                System.out.println("Times executed:" + algo_repet + "\n");
                writer.write("Times executed:" + algo_repet + "\n");
                textview.append("Times executed:" + algo_repet + "\n");

                System.out.println("***********************\n");
                writer.write("********************************\n");
                textview.append("**********************************\n");
            }

            if (library.equals("OpenSSL") && algo.equals("AES-OFB")) {
                System.out.println("***********OpenSSL/AES-OFB**************");
                writer.write("**********OpenSSL/AES-OFB***************\n");
                textview.append("**********OpenSSL/AES-OFB************\n");

                while (System.currentTimeMillis() < startTime + maxDurationInMilliseconds) {
                    OpenSSL test = new OpenSSL();
                    int[] timesAES = test.AESGCM();

                    System.out.println("Time to encrypt:" + timesAES[0] + "ms\n");
                    writer.write("Time to encrypt:" + timesAES[0] + "ms\n");
                    textview.append("Time to encrypt:" + timesAES[0] + "ms\n");


                    System.out.println("Time to decrypt:" + timesAES[1] + "ms\n");
                    writer.write("Time to decrypt:" + timesAES[1] + "ms\n");
                    textview.append("Time to decrypt:" + timesAES[1] + "ms\n");
                    textview.append("\n");
                    algo_repet += 1;
                }

                System.out.println("Times executed:" + algo_repet + "\n");
                writer.write("Times executed:" + algo_repet + "\n");
                textview.append("Times executed:" + algo_repet + "\n");

                System.out.println("***********************\n");
                writer.write("********************************\n");
                textview.append("**********************************\n");
            }

            if (library.equals("OpenSSL") && algo.equals("MD5")) {
                System.out.println("***********OpenSSL/MD5**************");
                writer.write("**********OpenSSL/MD5***************\n");
                textview.append("**********OpenSSL/MD5************\n");

                while (System.currentTimeMillis() < startTime + maxDurationInMilliseconds) {
                    OpenSSL test = new OpenSSL();
                    int[] testMD5 = test.MD5();
                    System.out.println("Time to generate hash:" + testMD5[0] + "ns\n");
                    writer.write("Time to generate hash:" + testMD5[0] + "ns\n");
                    textview.append("Time to generate hash:" + testMD5[0] + "ns\n");
                    textview.append("\n");
                    algo_repet += 1;
                }

                System.out.println("Times executed:" + algo_repet + "\n");
                writer.write("Times executed:" + algo_repet + "\n");
                textview.append("Times executed:" + algo_repet + "\n");

                System.out.println("***********************\n");
                writer.write("********************************\n");
                textview.append("**********************************\n");
            }

            if (library.equals("OpenSSL") && algo.equals("DH")) {
                System.out.println("***********OpenSSL/DH**************");
                writer.write("**********OpenSSL/DH***************\n");
                textview.append("**********OpenSSL/DH************\n");

                while (System.currentTimeMillis() < startTime + maxDurationInMilliseconds) {
                    OpenSSL test = new OpenSSL();
                    int[] testDH = test.DH();
                    System.out.println("Time to key agreement:" + testDH[1] + "ns\n");
                    writer.write("Time to key agreement:" + testDH[1] + "ns\n");
                    textview.append("Time to key agreement:" + testDH[1] + "ns\n");
                    textview.append("\n");
                    algo_repet += 1;
                }

                System.out.println("Times executed:" + algo_repet + "\n");
                writer.write("Times executed:" + algo_repet + "\n");
                textview.append("Times executed:" + algo_repet + "\n");

                System.out.println("***********************\n");
                writer.write("********************************\n");
                textview.append("**********************************\n");
            }

            if (library.equals("OpenSSL") && algo.equals("ECDH")) {
                System.out.println("***********OpenSSL/DH**************");
                writer.write("**********OpenSSL/DH***************\n");
                textview.append("**********OpenSSL/DH************\n");

                while (System.currentTimeMillis() < startTime + maxDurationInMilliseconds) {
                    OpenSSL test = new OpenSSL();
                    int[] testDH = test.ECDH();
                    System.out.println("Time to key agreement:" + testDH[1] + "ms\n");
                    writer.write("Time to key agreement:" + testDH[1] + "ms\n");
                    textview.append("Time to key agreement:" + testDH[1] + "ms\n");
                    textview.append("\n");
                    algo_repet += 1;
                }

                System.out.println("Times executed:" + algo_repet + "\n");
                writer.write("Times executed:" + algo_repet + "\n");
                textview.append("Times executed:" + algo_repet + "\n");

                System.out.println("***********************\n");
                writer.write("********************************\n");
                textview.append("**********************************\n");
            }

            if (library.equals("mbedTLS") && algo.equals("RSA")) {
                System.out.println("***********mbedTLS/RSA**************");
                writer.write("**********mbedTLS/RSA***************\n");
                textview.append("**********mbedTLS/RSA************\n");

                while (System.currentTimeMillis() < startTime + maxDurationInMilliseconds) {
                    mbedTLS test = new mbedTLS();
                    int[] timesRSA = test.RSA(64);

                    System.out.println("Time to encrypt:" + timesRSA[0] + "ms\n");
                    writer.write("Time to encrypt:" + timesRSA[0] + "ms\n");
                    textview.append("Time to encrypt:" + timesRSA[0] + "ms\n");


                    System.out.println("Time to decrypt:" + timesRSA[1] + "ms\n");
                    writer.write("Time to decrypt:" + timesRSA[1] + "ms\n");
                    textview.append("Time to decrypt:" + timesRSA[1] + "ms\n");
                    textview.append("\n");
                    algo_repet += 1;
                }

                System.out.println("Times executed:" + algo_repet + "\n");
                writer.write("Times executed:" + algo_repet + "\n");
                textview.append("Times executed:" + algo_repet + "\n");

                System.out.println("***********************\n");
                writer.write("********************************\n");
                textview.append("**********************************\n");

            }


            if (library.equals("mbedTLS") && algo.equals("AES-CBC")) {
                System.out.println("***********mbedTLS/AES**************");
                writer.write("**********mbedTLS/AES***************\n");
                textview.append("**********mbedTLS/AES************\n");

                while (System.currentTimeMillis() < startTime + maxDurationInMilliseconds) {
                    mbedTLS test = new mbedTLS();
                    int[] timesAES = test.AESCBC(64);

                    System.out.println("Time to encrypt:" + timesAES[0] + "ns\n");
                    writer.write("Time to encrypt:" + timesAES[0] + "ns\n");
                    textview.append("Time to encrypt:" + timesAES[0] + "ns\n");


                    System.out.println("Time to decrypt:" + timesAES[1] + "ns\n");
                    writer.write("Time to decrypt:" + timesAES[1] + "ns\n");
                    textview.append("Time to decrypt:" + timesAES[1] + "ns\n");
                    textview.append("\n");
                    algo_repet += 1;
                }

                System.out.println("Times executed:" + algo_repet + "\n");
                writer.write("Times executed:" + algo_repet + "\n");
                textview.append("Times executed:" + algo_repet + "\n");

                System.out.println("***********************\n");
                writer.write("********************************\n");
                textview.append("**********************************\n");
            }
            if (library.equals("mbedTLS") && algo.equals("AES-CTR")) {
                System.out.println("***********mbedTLS/AES**************");
                writer.write("**********mbedTLS/AES***************\n");
                textview.append("**********mbedTLS/AES************\n");

                while (System.currentTimeMillis() < startTime + maxDurationInMilliseconds) {
                    mbedTLS test = new mbedTLS();

                    int[] timesAES = test.AESCTR(64);

                    System.out.println("Time to encrypt:" + timesAES[0] + "ms\n");
                    writer.write("Time to encrypt:" + timesAES[0] + "ms\n");
                    textview.append("Time to encrypt:" + timesAES[0] + "ms\n");


                    System.out.println("Time to decrypt:" + timesAES[1] + "ms\n");
                    writer.write("Time to decrypt:" + timesAES[1] + "ms\n");
                    textview.append("Time to decrypt:" + timesAES[1] + "ms\n");
                    textview.append("\n");
                    algo_repet += 1;
                }

                System.out.println("Times executed:" + algo_repet + "\n");
                writer.write("Times executed:" + algo_repet + "\n");
                textview.append("Times executed:" + algo_repet + "\n");

                System.out.println("***********************\n");
                writer.write("********************************\n");
                textview.append("**********************************\n");
            }

            if (library.equals("mbedTLS") && algo.equals("AES-GCM")) {
                System.out.println("***********mbedTLS/AES-GCM**************");
                writer.write("**********mbedTLS/AES-GCM***************\n");
                textview.append("**********mbedTLS/AES-GCM************\n");

                while (System.currentTimeMillis() < startTime + maxDurationInMilliseconds) {
                    mbedTLS test = new mbedTLS();

                    int[] timesAES = test.AESGCM(64);

                    System.out.println("Time to encrypt:" + timesAES[0] + "ms\n");
                    writer.write("Time to encrypt:" + timesAES[0] + "ms\n");
                    textview.append("Time to encrypt:" + timesAES[0] + "ms\n");


                    System.out.println("Time to decrypt:" + timesAES[1] + "ms\n");
                    writer.write("Time to decrypt:" + timesAES[1] + "ms\n");
                    textview.append("Time to decrypt:" + timesAES[1] + "ms\n");
                    textview.append("\n");
                    algo_repet += 1;
                }

                System.out.println("Times executed:" + algo_repet + "\n");
                writer.write("Times executed:" + algo_repet + "\n");
                textview.append("Times executed:" + algo_repet + "\n");

                System.out.println("***********************\n");
                writer.write("********************************\n");
                textview.append("**********************************\n");
            }

            if (library.equals("mbedTLS") && algo.equals("MD5")) {
                System.out.println("***********mbedTLS/MD5**************");
                writer.write("**********mbedTLS/MD5***************\n");
                textview.append("**********mbedTLS/MD5************\n");

                while (System.currentTimeMillis() < startTime + maxDurationInMilliseconds) {
                    mbedTLS test = new mbedTLS();
                    int[] testMD5 = test.MD5(64);
                    System.out.println("Time to generate hash:" + testMD5[1] + "ns\n");
                    writer.write("Time to generate hash:" + testMD5[1] + "ns\n");
                    textview.append("Time to generate hash:" + testMD5[1] + "ns\n");
                    textview.append("\n");
                    algo_repet += 1;
                }

                System.out.println("Times executed:" + algo_repet + "\n");
                writer.write("Times executed:" + algo_repet + "\n");
                textview.append("Times executed:" + algo_repet + "\n");

                System.out.println("***********************\n");
                writer.write("********************************\n");
                textview.append("**********************************\n");
            }

            if (library.equals("mbedTLS") && algo.equals("ECDH")) {
                System.out.println("***********mbedTLS/ECDH**************");
                writer.write("**********mbedTLS/ECDH***************\n");
                textview.append("**********mbedTLS/ECDH************\n");

                while (System.currentTimeMillis() < startTime + maxDurationInMilliseconds) {
                    mbedTLS test = new mbedTLS();
                    int[] testECDH = test.ECDH();
                    System.out.println("Time to key agreement:" + testECDH[1] + "ms\n");
                    writer.write("Time to key agreement" + testECDH[1] + "ms\n");
                    textview.append("Time to key agreement:" + testECDH[1] + "ms\n");
                    textview.append("\n");
                    algo_repet += 1;
                }

                System.out.println("Times executed:" + algo_repet + "\n");
                writer.write("Times executed:" + algo_repet + "\n");
                textview.append("Times executed:" + algo_repet + "\n");

                System.out.println("***********************\n");
                writer.write("********************************\n");
                textview.append("**********************************\n");
            }

            if (library.equals("mbedTLS") && algo.equals("DH")) {
                System.out.println("***********mbedTLS/DH**************");
                writer.write("**********mbedTLS/DH***************\n");
                textview.append("**********mbedTLS/DH************\n");

                while (System.currentTimeMillis() < startTime + maxDurationInMilliseconds) {
                    mbedTLS test = new mbedTLS();
                    int[] testDH = test.DH();
                    System.out.println("Time to key agreement:" + testDH[1] + "ms\n");
                    writer.write("Time to key agreement" + testDH[1] + "ms\n");
                    textview.append("Time to key agreement:" + testDH[1] + "ms\n");
                    textview.append("\n");
                    algo_repet += 1;
                }

                System.out.println("Times executed:" + algo_repet + "\n");
                writer.write("Times executed:" + algo_repet + "\n");
                textview.append("Times executed:" + algo_repet + "\n");

                System.out.println("***********************\n");
                writer.write("********************************\n");
                textview.append("**********************************\n");
            }

            if (library.equals("WolfCrypt") && algo.equals("RSA")) {
                System.out.println("************WolfCrypt/RSA**************");
                textview.append("\n************WolfCrypt/RSA***************\n");
                writer.write("\n************WolfCrypt/RSA***************\n");
                while (System.currentTimeMillis() < startTime + maxDurationInMilliseconds) {
                    WolfCrypt test = new WolfCrypt();
                    int[] timesRSA = test.RSA(64);

                    System.out.println("Time to encrypt:" + timesRSA[0] + "ms\n");
                    writer.write("Time to encrypt:" + timesRSA[0] + "ms\n");
                    textview.append("Time to encrypt:" + timesRSA[0] + "ms\n");


                    System.out.println("Time to decrypt:" + timesRSA[1] + "ms\n");
                    writer.write("Time to decrypt:" + timesRSA[1] + "ms\n");
                    textview.append("Time to decrypt:" + timesRSA[1] + "ms\n");
                    textview.append("\n");
                    algo_repet += 1;
                }

                System.out.println("Times executed:" + algo_repet + "\n");
                writer.write("Times executed:" + algo_repet + "\n");
                textview.append("Times executed:" + algo_repet + "\n");

                System.out.println("********************************");
                writer.write("********************************\n");
                textview.append("********************************\n");
            }



            if (library.equals("WolfCrypt") && algo.equals("AES-CBC")) {
                System.out.println("************WolfCrypt/AES-CBC**************");
                textview.append("\n************WolfCrypt/AES-CBC***************\n");
                writer.write("\n************WolfCrypt/AES-CBC***************\n");

                while (System.currentTimeMillis() < startTime + maxDurationInMilliseconds) {
                    WolfCrypt test = new WolfCrypt();
                    int[] timesAES = test.AESCBC(64);

                    System.out.println("Time to encrypt:" + timesAES[0] + "ns\n");
                    writer.write("Time to encrypt:" + timesAES[0] + "ns\n");
                    textview.append("Time to encrypt:" + timesAES[0] + "ns\n");


                    System.out.println("Time to decrypt:" + timesAES[1] + "ns\n");
                    writer.write("Time to decrypt:" + timesAES[1] + "ns\n");
                    textview.append("Time to decrypt:" + timesAES[1] + "ns\n");
                    textview.append("\n");
                    algo_repet += 1;
                }

                System.out.println("Times executed:" + algo_repet + "\n");
                writer.write("Times executed:" + algo_repet + "\n");
                textview.append("Times executed:" + algo_repet + "\n");

                System.out.println("********************************");
                writer.write("********************************\n");
                textview.append("********************************\n");
            }

            if (library.equals("WolfCrypt") && algo.equals("AES-GCM")) {
                System.out.println("************WolfCrypt/AES-GCM**************");
                textview.append("\n************WolfCrypt/AES-GCM***************\n");
                writer.write("\n************WolfCrypt/AES-GCM***************\n");

                while (System.currentTimeMillis() < startTime + maxDurationInMilliseconds) {
                    WolfCrypt test = new WolfCrypt();
                    int[] timesAES = test.AESGCM(64);

                    System.out.println("Time to encrypt:" + timesAES[0] + "ns\n");
                    writer.write("Time to encrypt:" + timesAES[0] + "ns\n");
                    textview.append("Time to encrypt:" + timesAES[0] + "ns\n");


                    System.out.println("Time to decrypt:" + timesAES[1] + "ns\n");
                    writer.write("Time to decrypt:" + timesAES[1] + "ns\n");
                    textview.append("Time to decrypt:" + timesAES[1] + "ns\n");
                    textview.append("\n");
                    algo_repet += 1;
                }

                System.out.println("Times executed:" + algo_repet + "\n");
                writer.write("Times executed:" + algo_repet + "\n");
                textview.append("Times executed:" + algo_repet + "\n");

                System.out.println("********************************");
                writer.write("********************************\n");
                textview.append("********************************\n");
            }

            if (library.equals("WolfCrypt") && algo.equals("AES-CTR")) {
                System.out.println("************WolfCrypt/AES-CTR**************");
                textview.append("\n************WolfCrypt/AES-CTR***************\n");
                writer.write("\n************WolfCrypt/AES-CTR***************\n");

                while (System.currentTimeMillis() < startTime + maxDurationInMilliseconds) {
                    WolfCrypt test = new WolfCrypt();
                    int[] timesAES = test.AESCTR(64);

                    System.out.println("Time to encrypt:" + timesAES[0] + "ms\n");
                    writer.write("Time to encrypt:" + timesAES[0] + "ms\n");
                    textview.append("Time to encrypt:" + timesAES[0] + "ns\n");


                    System.out.println("Time to decrypt:" + timesAES[1] + "ms\n");
                    writer.write("Time to decrypt:" + timesAES[1] + "ms\n");
                    textview.append("Time to decrypt:" + timesAES[1] + "ms\n");
                    textview.append("\n");
                    algo_repet += 1;
                }

                System.out.println("Times executed:" + algo_repet + "\n");
                writer.write("Times executed:" + algo_repet + "\n");
                textview.append("Times executed:" + algo_repet + "\n");

                System.out.println("********************************");
                writer.write("********************************\n");
                textview.append("********************************\n");
            }

            if (library.equals("WolfCrypt") && algo.equals("MD5")) {
                System.out.println("************WolfCrypt/MD5**************");
                textview.append("\n************WolfCrypt/MD5***************\n");
                writer.write("\n************WolfCrypt/MD5***************\n");

                while (System.currentTimeMillis() < startTime + maxDurationInMilliseconds) {
                    WolfCrypt test = new WolfCrypt();
                    int[] testMD5 = test.MD5(64);
                    System.out.println("Time to generate hash:" + testMD5[1] + "ns\n");
                    writer.write("Time to generate hash:" + testMD5[1] + "ns\n");
                    textview.append("Time to generate hash:" + testMD5[1] + "ns\n");
                    textview.append("\n");
                    algo_repet += 1;
                }

                System.out.println("Times executed:" + algo_repet + "\n");
                writer.write("Times executed:" + algo_repet + "\n");
                textview.append("Times executed:" + algo_repet + "\n");

                System.out.println("********************************");
                writer.write("********************************\n");
                textview.append("********************************\n");
            }

            if (library.equals("WolfCrypt") && algo.equals("DH")) {
                System.out.println("************WolfCrypt/DH**************");
                textview.append("\n************WolfCrypt/DH***************\n");
                writer.write("\n************WolfCrypt/DH***************\n");
                while (System.currentTimeMillis() < startTime + maxDurationInMilliseconds) {
                    WolfCrypt test = new WolfCrypt();
                    int[] testDH = test.DH();
                    System.out.println("Time to key agreement:" + testDH[1] + "ns\n");
                    writer.write("Time to key agreement:" + testDH[1] + "ns\n");
                    textview.append("Time to key agreement:" + testDH[1] + "ns\n");
                    textview.append("\n");
                    algo_repet += 1;
                }

                System.out.println("Times executed:" + algo_repet + "\n");
                writer.write("Times executed:" + algo_repet + "\n");
                textview.append("Times executed:" + algo_repet + "\n");

                System.out.println("********************************");
                writer.write("********************************\n");
                textview.append("********************************\n");
            }

            if (library.equals("WolfCrypt") && algo.equals("ECDH")) {
                System.out.println("************WolfCrypt/ECDH**************");
                textview.append("\n************WolfCrypt/ECDH***************\n");
                writer.write("\n************WolfCrypt/ECDH***************\n");
                while (System.currentTimeMillis() < startTime + maxDurationInMilliseconds) {
                    WolfCrypt test = new WolfCrypt();
                    int[] testDH = test.ECDH();
                    System.out.println("Time to key agreement:" + testDH[1] + "ns\n");
                    writer.write("Time to key agreement:" + testDH[1] + "ns\n");
                    textview.append("Time to key agreement:" + testDH[1] + "ns\n");
                    textview.append("\n");
                    algo_repet += 1;
                }

                System.out.println("Times executed:" + algo_repet + "\n");
                writer.write("Times executed:" + algo_repet + "\n");
                textview.append("Times executed:" + algo_repet + "\n");

                System.out.println("********************************");
                writer.write("********************************\n");
                textview.append("********************************\n");
            }

            if (library.equals("Bouncy Castle") && algo.equals("RSA")) {
                RSAImplementation test = new RSAImplementation();
                try {
                    test.RSA(writer, textview, resulttime);
                } catch (Exception i) {
                    throw new RuntimeException(i);
                }
            }

            if (library.equals("Bouncy Castle") && algo.equals("RSA2")) {
                RSAPrueba test = new RSAPrueba();
                try {
                    test.testRSA();
                } catch (Exception i) {
                    throw new RuntimeException(i);
                }
            }

            if (library.equals("Bouncy Castle") && algo.equals("AES-CBC")) {
                AESCBCBouncyCastleImplementation test = new AESCBCBouncyCastleImplementation();
                try {
                    test.AESCBC(writer, textview, resulttime);
                } catch (Exception i) {
                    throw new RuntimeException(i);
                }
            }

            if (library.equals("Bouncy Castle") && algo.equals("AES-CTR")) {

                System.out.println("************Bouncy Castle/AES-CTR**************");
                textview.append("\n************Bouncy Castle/AES-CTR***************\n");
                writer.write("\n************Bouncy Castle/AES-CTR***************\n");

                while (System.currentTimeMillis() < startTime + maxDurationInMilliseconds) {
                    AESCTR test = new AESCTR();
                    try {
                        test.testCTR();
                    } catch (Exception i) {
                        throw new RuntimeException(i);
                    }
                }

                System.out.println("********************************");
                writer.write("********************************\n");
                textview.append("********************************\n");
            }

            if (library.equals("Bouncy Castle") && algo.equals("AES-GCM")) {

                System.out.println("************Bouncy Castle/AES-GCM**************");
                textview.append("\n************Bouncy Castle/AES-GCM***************\n");
                writer.write("\n************Bouncy Castle/AES-GCM***************\n");

                while (System.currentTimeMillis() < startTime + maxDurationInMilliseconds) {
                    AESGCM test = new AESGCM();
                    try {
                        test.testGCM();
                    } catch (Exception i) {
                        throw new RuntimeException(i);
                    }
                }

                System.out.println("********************************");
                writer.write("********************************\n");
                textview.append("********************************\n");
            }

            if (library.equals("Bouncy Castle") && algo.equals("AES-OFB")) {

                System.out.println("************Bouncy Castle/AES-OFB**************");
                textview.append("\n************Bouncy Castle/AES-OFB***************\n");
                writer.write("\n************Bouncy Castle/AES-OFB***************\n");

                while (System.currentTimeMillis() < startTime + maxDurationInMilliseconds) {
                    AESOFB test = new AESOFB();
                    try {
                        test.testOFB();
                    } catch (Exception i) {
                        throw new RuntimeException(i);
                    }
                }

                System.out.println("********************************");
                writer.write("********************************\n");
                textview.append("********************************\n");
            }


            if (library.equals("Bouncy Castle") && algo.equals("MD5")) {
                while (System.currentTimeMillis() < startTime + maxDurationInMilliseconds) {
                    MD5Implementation test = new MD5Implementation();
                    try {
                        test.testmd5(writer, textview, resulttime);
                    } catch (Exception i) {
                        throw new RuntimeException(i);
                    }
                }
            }

            if (library.equals("Bouncy Castle") && algo.equals("DH")) {
                while (System.currentTimeMillis() < startTime + maxDurationInMilliseconds) {
                    DiffieHellman test = new DiffieHellman();
                    try {
                        test.testDH();
                    } catch (Exception i) {
                        throw new RuntimeException(i);
                    }
                }
            }

            if (library.equals("Bouncy Castle") && algo.equals("ECDH")) {
                while (System.currentTimeMillis() < startTime + maxDurationInMilliseconds) {
                    ECDiffieHellmanImplementation test = new ECDiffieHellmanImplementation();
                    try {
                        test.startDiffieHellman(writer, textview, resulttime);
                    } catch (Exception i) {
                        throw new RuntimeException(i);
                    }
                }
            }

            writer.close();

            final String titel = System.getProperty("os.arch");
            final GMailSender sender = new GMailSender("encryptapp.report@gmail.com",
                    "EncryptAppReport");
            new AsyncTask<Void, Void, Void>() {
                @Override
                public Void doInBackground(Void... arg) {
                    try {
                        sender.sendMail("Report",
                                "Special Test",
                                "encr" +
                                        "yptapp.report@gmail.com",
                                "encryptapp.report@gmail.com",
                                report);
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

    @Override
    public void onItemSelected(AdapterView<?> adapterView, View view, int i, long l) {

    }

    @Override
    public void onNothingSelected(AdapterView<?> adapterView) {

    }
}


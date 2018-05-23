package com.example.juanperezdealgaba.sac;

import android.app.Activity;
import android.content.Intent;
import android.os.Build;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.text.method.ScrollingMovementMethod;
import android.view.View;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.Spinner;
import android.widget.TextView;

import com.snatik.storage.Storage;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

import static android.provider.AlarmClock.EXTRA_MESSAGE;

public class ConcreteTest extends AppCompatActivity implements AdapterView.OnItemSelectedListener{

    public static String library;
    public static String algo;

    @Override
    protected void onCreate(Bundle savedInstanceState) {


            super.onCreate(savedInstanceState);
            setContentView(R.layout.activity_concrete_test);

            final TextView results_special_test = (TextView) findViewById(R.id.special_test_results);

            results_special_test.setMovementMethod(new ScrollingMovementMethod());

            Storage storage = new Storage(getApplicationContext());

            String path = storage.getExternalStorageDirectory();

            final String newDir = path + File.separator + "Encryptapp";

            final File report = new File(newDir, "Report.txt");
            report.mkdirs();

            if (report.exists())
                report.delete();


            Spinner spinner_algo = (Spinner) findViewById(R.id.spinner_algo);
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

            Spinner spinner_library = (Spinner) findViewById(R.id.spinner_library);
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

            final Button start_test = (Button) findViewById(R.id.button_special_test);
            start_test.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View view) {
                        createAlgo(library, algo, results_special_test,report);
                }
            });



    }

    public void createAlgo (String library, String algo, TextView textview,File report){
        int repetitions = 5;



        try {
            final FileWriter writer = new FileWriter(report);
            String myVersion = android.os.Build.VERSION.RELEASE;
            int sdkVersion = android.os.Build.VERSION.SDK_INT;
            String manufacturer = Build.MANUFACTURER;
            String device = Build.DEVICE;
            String model = Build.MODEL;

            String model_cpu = System.getProperty("os.arch");


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
                BoringSSL test = new BoringSSL();
                test.RSA();
            }

            if (library.equals("BoringSSL") && algo.equals("AES")) {
                BoringSSL test = new BoringSSL();
                test.AES();
            }
            if (library.equals("BoringSSL") && algo.equals("MD5")) {
                BoringSSL test = new BoringSSL();
                test.MD5();
            }

            if (library.equals("BoringSSL") && algo.equals("DH")) {
                BoringSSL test = new BoringSSL();
                test.DH();
            }

            if (library.equals("OpenSSL") && algo.equals("RSA")) {
                OpenSSL test = new OpenSSL();
                test.RSA(2);
            }

            if (library.equals("OpenSSL") && algo.equals("AES")) {
                OpenSSL test = new OpenSSL();
                test.AES(2);
            }
            if (library.equals("OpenSSL") && algo.equals("MD5")) {
                OpenSSL test = new OpenSSL();
                test.MD5();
            }

            if (library.equals("OpenSSL") && algo.equals("DH")) {
                OpenSSL test = new OpenSSL();
                test.DH();
            }

            if (library.equals("mbedTLS") && algo.equals("RSA")) {
                mbedTLS test = new mbedTLS();
                test.RSA();
            }

            if (library.equals("mbedTLS") && algo.equals("AES")) {
                mbedTLS test = new mbedTLS();
                test.AES();
            }
            if (library.equals("mbedTLS") && algo.equals("MD5")) {
                mbedTLS test = new mbedTLS();
                test.MD5();
            }

            if (library.equals("mbedTLS") && algo.equals("DH")) {
                mbedTLS test = new mbedTLS();
                test.DH();
            }

            if (library.equals("WolfCrypt") && algo.equals("RSA")) {
                System.out.println("************WolfCrypt/RSA**************");
                textview.append("\n************WolfCrypt/RSA***************\n");
                writer.write("\n************WolfCrypt/RSA***************\n");
                for(int i = 0; i < repetitions; i++) {
                    WolfCrypt test = new WolfCrypt();
                    test.RSA();
                }

                System.out.println("********************************");
                writer.write("********************************\n");
                textview.append("********************************\n");
            }

            if (library.equals("WolfCrypt") && algo.equals("AES")) {
                System.out.println("************WolfCrypt/AES-CBC**************");
                textview.append("\n************WolfCrypt/AES-CBC***************\n");
                writer.write("\n************WolfCrypt/AES-CBC***************\n");

                for(int i = 0; i < repetitions; i++) {
                    WolfCrypt test = new WolfCrypt();
                    double[] timesAES = test.AES();

                    System.out.println("Time to encrypt:" + timesAES[0] + "ns\n");
                    writer.write("Time to encrypt:" + timesAES[0] + "ns\n");
                    textview.append("Time to encrypt:" + timesAES[0] + "ns\n");


                    System.out.println("Time to decrypt:" + timesAES[1] + "ns\n");
                    writer.write("Time to decrypt:" + timesAES[1] + "ns\n");
                    textview.append("Time to decrypt:" + timesAES[1] + "ns\n");
                    textview.append("\n");
                }
                System.out.println("********************************");
                writer.write("********************************\n");
                textview.append("********************************\n");
            }
            if (library.equals("WolfCrypt") && algo.equals("MD5")) {
                System.out.println("************WolfCrypt/MD5**************");
                textview.append("\n************WolfCrypt/MD5***************\n");
                writer.write("\n************WolfCrypt/MD5***************\n");

                for (int i = 0; i < repetitions; i++) {
                    WolfCrypt test = new WolfCrypt();
                    double[] testMD5 = test.MD5();
                    System.out.println("Time to generate hash:" + testMD5[1] + "ns\n");
                    writer.write("Time to generate hash:" + testMD5[1] + "ns\n");
                    textview.append("Time to generate hash:" + testMD5[1] + "ns\n");
                    textview.append("\n");
                }
                System.out.println("********************************");
                writer.write("********************************\n");
                textview.append("********************************\n");
            }

            if (library.equals("WolfCrypt") && algo.equals("DH")) {
                System.out.println("************WolfCrypt/DH**************");
                textview.append("\n************WolfCrypt/DH***************\n");
                writer.write("\n************WolfCrypt/DH***************\n");
                for (int i = 0; i < repetitions; i++) {
                    WolfCrypt test = new WolfCrypt();
                    double[] testDH = test.DH();
                    System.out.println("Time to key agreement:" + testDH[1] + "ns\n");
                    writer.write("Time to key agreement:" + testDH[1] + "ns\n");
                    textview.append("Time to key agreement:" + testDH[1] + "ns\n");
                    textview.append("\n");
                }
                System.out.println("********************************");
                writer.write("********************************\n");
                textview.append("********************************\n");
            }

            if (library.equals("Bouncy Castle") && algo.equals("RSA")) {
                RSAImplementation test = new RSAImplementation();
                try {
                    test.RSA(writer, textview, repetitions);
                } catch (Exception i) {
                    throw new RuntimeException(i);
                }
            }

            if (library.equals("Bouncy Castle") && algo.equals("AES")) {
                AESCBCBouncyCastleImplementation test = new AESCBCBouncyCastleImplementation();
                try {
                    test.AESCBC(writer, textview, repetitions);
                } catch (Exception i) {
                    throw new RuntimeException(i);
                }
            }

            if (library.equals("Bouncy Castle") && algo.equals("MD5")) {
                MD5Implementation test = new MD5Implementation();
                try {
                    test.testmd5(writer, textview, repetitions);
                } catch (Exception i) {
                    throw new RuntimeException(i);
                }
            }

            if (library.equals("Bouncy Castle") && algo.equals("DH")) {
                DiffieHellmanImplementation test = new DiffieHellmanImplementation();
                try {
                    test.startDiffieHellman(writer, textview, repetitions);
                } catch (Exception i) {
                    throw new RuntimeException(i);
                }
            }

            writer.close();

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


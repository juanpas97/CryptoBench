package com.example.juanperezdealgaba.sac;

import android.app.Activity;
import android.content.Intent;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.view.View;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.Spinner;

import static android.provider.AlarmClock.EXTRA_MESSAGE;

public class ConcreteTest extends AppCompatActivity implements AdapterView.OnItemSelectedListener{

    public static String library;
    public static String algo;

    @Override
    protected void onCreate(Bundle savedInstanceState) {

        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_concrete_test);

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

                if(algo.equals("RSA")){
                    System.out.println("RSA");
                }

                if(algo.equals("DH")){
                    System.out.println("DH");
                }

                if(algo.equals("MD-5")){
                    System.out.println("MD-5");
                }

                if(algo.equals("AES")){
                    System.out.println("AES");
                }
            }

            @Override
            public void onNothingSelected(AdapterView<?> adapterView) {

            }
        });

        Spinner spinner_library = (Spinner) findViewById(R.id.spinner_library);
// Create an ArrayAdapter using the string array and a default spinner layout
        ArrayAdapter<CharSequence> adapterlibrary= ArrayAdapter.createFromResource(this,
                R.array.libraries_array, android.R.layout.simple_spinner_item);
// Specify the layout to use when the list of choices appears
        adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
// Apply the adapter to the spinner
        spinner_library.setAdapter(adapterlibrary);

        spinner_library.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override
            public void onItemSelected(AdapterView<?> adapterView, View view, int i, long l) {
                library = adapterView.getItemAtPosition(i).toString();

                if(library.equals("Bouncy Castle")){
                    System.out.println("Bouncy Castle");
                }

                if(library.equals("WolfCrypt")){
                    System.out.println("WolfCrypt");
                }

                if(library.equals("mbedTLS")){
                    System.out.println("mbedTLS");
                }

                if(library.equals("OpenSSL")){
                    System.out.println("OpenSSL");
                }

                if(library.equals("BoringSSL")){
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
                createAlgo(library,algo);
            }
        });

    }

    public void createAlgo(String library, String algo){

        if(library.equals("BoringSSL") && algo.equals("RSA") ){
            BoringSSL test = new BoringSSL();
            test.RSA();
        }

        if(library.equals("BoringSSL") && algo.equals("AES") ){
            BoringSSL test = new BoringSSL();
            test.AES();
        }
        if(library.equals("BoringSSL") && algo.equals("MD5") ){
            BoringSSL test = new BoringSSL();
            test.MD5();
        }

        if(library.equals("BoringSSL") && algo.equals("DH") ){
            BoringSSL test = new BoringSSL();
            test.DH();
        }

        if(library.equals("OpenSSL") && algo.equals("RSA") ){
            OpenSSL test = new OpenSSL();
            test.RSA(2);
        }

        if(library.equals("OpenSSL") && algo.equals("AES") ){
            OpenSSL test = new OpenSSL();
            test.AES(2);
        }
        if(library.equals("OpenSSL") && algo.equals("MD5") ){
                OpenSSL test = new OpenSSL();
                test.MD5();
        }

        if(library.equals("OpenSSL") && algo.equals("DH") ){
            OpenSSL test = new OpenSSL();
            test.DH();
        }

        if(library.equals("mbedTLS") && algo.equals("RSA") ){
            mbedTLS test = new mbedTLS();
            test.RSA();
        }

        if(library.equals("mbedTLS") && algo.equals("AES") ){
            mbedTLS test = new mbedTLS();
            test.AES();
        }
        if(library.equals("mbedTLS") && algo.equals("MD5") ){
            mbedTLS test = new mbedTLS();
            test.MD5();
        }

        if(library.equals("mbedTLS") && algo.equals("DH") ){
            mbedTLS test = new mbedTLS();
            test.DH();
        }

        if(library.equals("WolfCrypt") && algo.equals("RSA") ){
            WolfCrypt test = new WolfCrypt();
            test.RSA();
        }

        if(library.equals("WolfCrypt") && algo.equals("AES") ){
            WolfCrypt test = new WolfCrypt();
            test.AES();
        }
        if(library.equals("WolfCrypt") && algo.equals("MD5") ){
            WolfCrypt test = new WolfCrypt();
            test.MD5();
        }

        if(library.equals("WolfCrypt") && algo.equals("DH") ){
            WolfCrypt test = new WolfCrypt();
            test.DH();
        }

        if(library.equals("Bouncy Castle") && algo.equals("RSA") ){
            RSAImplementation test= new RSAImplementation();
            try {
                test.RSA();
            }catch(Exception i){
                throw new RuntimeException(i);
            }
        }

        if(library.equals("Bouncy Castle") && algo.equals("AES") ){
            AESCBCBouncyCastleImplementation test= new AESCBCBouncyCastleImplementation();
            try {
                test.AESCBC();
            }catch(Exception i){
                throw new RuntimeException(i);
            }
        }

        if(library.equals("Bouncy Castle") && algo.equals("MD5") ){
            MD5Implementation test= new MD5Implementation();
            try {
                test.testmd5();
            }catch(Exception i){
                throw new RuntimeException(i);
            }
        }

        if(library.equals("Bouncy Castle") && algo.equals("DH") ){
            DiffieHellmanImplementation test= new DiffieHellmanImplementation();
            try {
                test.startDiffieHellman();
            }catch(Exception i){
                throw new RuntimeException(i);
            }
        }

    }

    @Override
    public void onItemSelected(AdapterView<?> adapterView, View view, int i, long l) {

    }

    @Override
    public void onNothingSelected(AdapterView<?> adapterView) {

    }
}


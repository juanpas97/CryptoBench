package com.example.CryptoBench.sac;

import android.app.Activity;
import android.content.Intent;
import android.os.AsyncTask;
import android.os.Bundle;
import android.support.design.widget.FloatingActionButton;
import android.support.design.widget.Snackbar;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.Toolbar;
import android.text.method.ScrollingMovementMethod;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;

import com.snatik.storage.Storage;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

import static android.util.Config.LOGD;

public class CompleteTestActivity extends AppCompatActivity{

    @Override
    protected void onCreate(Bundle savedInstanceState) {


            super.onCreate(savedInstanceState);
            setContentView(R.layout.activity_complete_test);
            Toolbar toolbar = (Toolbar) findViewById(R.id.toolbar);
            setSupportActionBar(toolbar);

            final TextView complete_test_results = findViewById(R.id.complete_test_results);

            complete_test_results.setMovementMethod(new ScrollingMovementMethod());

            final EditText repetitions_test = findViewById(R.id.repetitions);

            final EditText repetitions_aes = findViewById(R.id.repetitions_aes);

            final EditText repetitions_rsa = findViewById(R.id.repetitions_rsa);

            final EditText repetitions_hash = findViewById(R.id.repetitions_hash);

            final EditText repetitions_agree = findViewById(R.id.repetitions_agree);

            final EditText rep_aes = findViewById(R.id.title_aes);

            final EditText rep_rsa = findViewById(R.id.title_rsa);

            final EditText rep_agree = findViewById(R.id.title_agree);

            final EditText rep_hash = findViewById(R.id.title_hash);

            final Button start_test = findViewById(R.id.start_complete_test);

            final Storage storage = new Storage(getApplicationContext());

            Intent intent = getIntent();
            Bundle extras = intent.getExtras();
            int rep_shell,rep_aes_shell,rep_hash_shell,rep_agree_shell,rep_rsa_shell;

        if ( extras != null ) {

            for (String key : extras.keySet()) {
                Object value = extras.get(key);
                Log.d("BUNDLE", String.format("%s %s (%s)", key,
                        value.toString(), value.getClass().getName()));
            }

            if ( extras.containsKey ( "test" ) ) {
                System.out.println("We started shell");
                String rep =extras.getString ( "test" );
                rep_shell = Integer.parseInt(rep);
            } else {
                rep_shell = 1;
            }

            System.out.println("TEST SKIPPED");
            if ( extras.containsKey ( "aes" ) ) {
                System.out.println("AES SHELL");
                String rep = extras.getString ( "aes" );
                rep_aes_shell = Integer.parseInt(rep);
                System.out.println("AES SHELL IS: " + rep_aes);
            } else {
                rep_aes_shell = 10;
            }

            if ( extras.containsKey ( "hash" ) ) {
                String rep =extras.getString ( "hash" );
                rep_hash_shell = Integer.parseInt(rep);
            } else {
                rep_hash_shell = 10;
            }

            if ( extras.containsKey ( "dh" ) ) {
                String rep =extras.getString ( "dh" );
                rep_agree_shell = Integer.parseInt(rep);
            } else {
                rep_agree_shell = 10;
            }

            if ( extras.containsKey ( "rsa" ) ) {
                String rep =extras.getString ( "rsa" );
                rep_rsa_shell = Integer.parseInt(rep);
            } else {
                rep_rsa_shell = 10;
            }

            System.out.println("Shell function");
            CompleteTestParams paramsTest = new CompleteTestParams(storage, complete_test_results,rep_shell,rep_aes_shell,rep_hash_shell,rep_agree_shell,rep_rsa_shell);

            CompleteTestAsync test = new CompleteTestAsync(CompleteTestActivity.this);
            test.execute(paramsTest);
        }




        start_test.setOnClickListener(new View.OnClickListener() {

                @Override
                public void onClick(View view) {

                    int repetitions,rep_aes, rep_rsa,rep_agree,rep_hash;

                    complete_test_results.setText("");

                    String check = repetitions_test.getText().toString();
                    if (check.matches("")) {
                        repetitions = 1;
                    } else {
                        repetitions = Integer.parseInt(repetitions_test.getText().toString());
                    }

                    String check_aes = repetitions_aes.getText().toString();
                    if (check_aes.matches("")) {
                        rep_aes = 10;
                    } else {
                        rep_aes = Integer.parseInt(repetitions_aes.getText().toString());
                    }

                    String check_rsa = repetitions_rsa.getText().toString();
                    if (check_rsa.matches("")) {
                        rep_rsa = 10;
                    } else {
                        rep_rsa = Integer.parseInt(repetitions_rsa.getText().toString());
                    }

                    String check_hash = repetitions_hash.getText().toString();
                    if (check_hash.matches("")) {
                        rep_hash = 10;
                    } else {
                        rep_hash = Integer.parseInt(repetitions_hash.getText().toString());
                    }

                    String check_agree = repetitions_agree.getText().toString();
                    if (check_agree.matches("")) {
                        rep_agree = 10;
                    } else {
                        rep_agree = Integer.parseInt(repetitions_agree.getText().toString());
                    }

                    System.out.println("Repetitions:" + repetitions);
                    System.out.println("Rep_aes: " + rep_aes);

                    CompleteTestParams paramsTest = new CompleteTestParams(storage, complete_test_results,repetitions,rep_aes,rep_hash,rep_agree,rep_rsa);

                    CompleteTestAsync test = new CompleteTestAsync(CompleteTestActivity.this);
                    test.execute(paramsTest);

                }
            });
    }
}
